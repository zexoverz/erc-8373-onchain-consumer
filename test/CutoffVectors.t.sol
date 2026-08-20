// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PQCutoffEnforcer} from "../src/PQCutoffEnforcer.sol";
import {IPQAnchorRegistry, IPQCompanionVerifier, PQVerdict} from "../src/IPQKeyBindingConsumer.sol";

/// @notice A substrate replaying the anchor times the vectors record. It answers exactly what the
///         vector file says and nothing else, so the enforcer is driven by their data rather than
///         by anything invented here.
contract VectorAnchorSubstrate is IPQAnchorRegistry {
    mapping(bytes32 => uint64) private _t;
    mapping(bytes32 => address) private _by;

    function anchor(bytes32 ca, uint64 t, address by) external {
        _t[ca] = t;
        _by[ca] = by;
    }

    function anchorTimeOf(bytes32 ca) external view returns (uint64) {
        return _t[ca];
    }

    function anchoredBy(bytes32 ca) external view returns (address) {
        return _by[ca];
    }
}

/// @notice Companion validity as the vectors supply it. The vector file states plainly that
///         signature validity "is the deep lane, supplied here as evidence (pq_companion.valid) so
///         the policy is recomputable independent of any crypto lib". This takes them at their
///         word: the policy is what is under test, not ML-DSA arithmetic.
contract VectorCompanionVerifier is IPQCompanionVerifier {
    bool public valid;
    bool public underInForceKey;

    function set(bool valid_, bool underInForceKey_) external {
        valid = valid_;
        underInForceKey = underInForceKey_;
    }

    function algorithm() external pure returns (string memory) {
        return "SLH-DSA-SHA2-192s";
    }

    /// A companion that is cryptographically valid but signed under a key that is not the in-force
    /// one MUST NOT count. The vectors carry that as its own case.
    function verifyCompanion(bytes32, bytes calldata, bytes calldata) external view returns (bool) {
        return valid && underInForceKey;
    }
}

/// @notice Drives the reference enforcer with the published ERC-8373 cutoff vectors.
contract CutoffVectorsTest is Test {
    string constant VECTORS = "vectors/pq-key-binding-v0.cutoff-vectors.json";
    address constant CLASSICAL = 0xFf9a176577Fb42b6bc9c19fd05a241e8fCd0ca14; // from the vectors

    bytes32 constant GENESIS = keccak256("kya-l4-genesis");
    bytes32 constant REVOKE_REC = keccak256("kya-l4-revocation");

    string json;
    uint64 consumerCutoff;
    uint64 bindingAnchor;
    uint256 caseCount;

    function setUp() public {
        json = vm.readFile(VECTORS);
        consumerCutoff = uint64(vm.parseJsonUint(json, ".consumer_cutoff"));
        bindingAnchor = uint64(vm.parseJsonUint(json, ".bindings[0].binding_anchor_time"));
        while (vm.keyExistsJson(json, string.concat(_path(caseCount), ".artifact.anchor_time"))) {
            caseCount++;
        }
    }

    function _path(uint256 i) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "]");
    }

    /// Build a fresh enforcer for one case, honouring a per-case revocation override if present.
    function _enforcerFor(uint256 i, VectorCompanionVerifier ver)
        internal
        returns (PQCutoffEnforcer enf, VectorAnchorSubstrate sub)
    {
        sub = new VectorAnchorSubstrate();
        sub.anchor(GENESIS, bindingAnchor, CLASSICAL);
        enf = new PQCutoffEnforcer(consumerCutoff, sub, ver, CLASSICAL);
        enf.registerBinding(GENESIS, bytes32(0), hex"638c");

        string memory revPath = string.concat(_path(i), ".bindings[0].revoked_at");
        if (vm.keyExistsJson(json, revPath)) {
            uint64 revokedAt = uint64(vm.parseJsonUint(json, revPath));
            sub.anchor(REVOKE_REC, revokedAt, CLASSICAL);
            enf.revokeBinding(GENESIS, REVOKE_REC);
        }
    }

    function _runCase(uint256 i) internal returns (PQVerdict got, string memory expected) {
        VectorCompanionVerifier ver = new VectorCompanionVerifier();
        (PQCutoffEnforcer enf, VectorAnchorSubstrate sub) = _enforcerFor(i, ver);

        uint64 anchorTime = uint64(vm.parseJsonUint(json, string.concat(_path(i), ".artifact.anchor_time")));
        bytes32 artifact = keccak256(abi.encode("artifact", i));
        sub.anchor(artifact, anchorTime, CLASSICAL);

        bytes memory companion;
        string memory presentPath = string.concat(_path(i), ".artifact.pq_companion.present");
        if (vm.keyExistsJson(json, presentPath)) {
            companion = hex"5165";
            bool isValid = vm.parseJsonBool(json, string.concat(_path(i), ".artifact.pq_companion.valid"));
            // The "valid companion under a NON-in-force key" case carries a pq_pubkey that is not
            // the in-force one. Detect it by comparing against the binding's key prefix.
            string memory keyPath = string.concat(_path(i), ".artifact.pq_companion.pq_pubkey");
            bool inForceKey = true;
            if (vm.keyExistsJson(json, keyPath)) {
                string memory k = vm.parseJsonString(json, keyPath);
                inForceKey = _startsWith(k, "638c");
            }
            ver.set(isValid, inForceKey);
        }

        got = enf.verifyArtifact(artifact, companion);
        expected = vm.parseJsonString(json, string.concat(_path(i), ".expected.decision"));
    }

    function _startsWith(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory b = bytes(s);
        bytes memory p = bytes(prefix);
        if (b.length < p.length) return false;
        for (uint256 i = 0; i < p.length; i++) {
            if (b[i] != p[i]) return false;
        }
        return true;
    }

    function _asVerdict(string memory decision) internal pure returns (PQVerdict) {
        bytes32 h = keccak256(bytes(decision));
        if (h == keccak256("ADMIT") || h == keccak256("ACCEPT")) return PQVerdict.Accept;
        if (h == keccak256("REJECT")) return PQVerdict.Reject;
        return PQVerdict.Unverifiable;
    }

    /// The vector file is the source of truth, so first assert we are reading the file we think we
    /// are. If these move, every conclusion below has to be re-derived.
    function test_vector_file_is_the_published_one() public view {
        assertEq(consumerCutoff, 1790000000);
        assertEq(bindingAnchor, 1785423299);
        assertEq(caseCount, 8);
    }

    /// Six of the eight published cases are reproduced exactly by the on-chain enforcer.
    ///
    /// The two that are not are listed below and asserted separately, because they disagree with
    /// the ERC's own normative text rather than with this implementation.
    function test_enforcer_reproduces_the_undisputed_vectors() public {
        uint256 agreed;
        for (uint256 i = 0; i < caseCount; i++) {
            if (i == 5) continue; // the one remaining disputed case
            (PQVerdict got, string memory expected) = _runCase(i);
            assertEq(
                uint256(got),
                uint256(_asVerdict(expected)),
                string.concat("case ", vm.toString(i), " disagrees with the published vector")
            );
            agreed++;
        }
        assertEq(agreed, 7);
    }

    // ── The one disputed case that remains ───────────────────────────────────
    //
    // TMerlini confirmed on the thread that the published v0 vectors carry a real inconsistency,
    // and sharpened it: `no_in_force_binding` is doing double duty over two cases that deserve
    // opposite answers.
    //
    //   pre-baseline    anchored before the first binding was registered. Innocent back
    //                   catalogue, must admit classical-only.
    //   post-revocation anchored after a binding's authority was deliberately ended. A revocation
    //                   is a trust-ending act whose signal outranks the consumer's cutoff, so it
    //                   must be refused even pre-cutoff.
    //
    // The v1 profile fixes the first by activating the baseline at 0. This enforcer implements v1,
    // so it now agrees with the published vector on the post-revocation case and disagrees only on
    // the pre-baseline one, which is the half the ERC's shipped assets have not caught up with.

    /// Anchored at 1785000000, before the genesis binding existed, and before the cutoff. Under v1
    /// the baseline governs from creation, so this resolves and the cutoff admits it classical-only.
    /// The shipped v0 vector rejects it. That gap is the one being remediated by advancing the
    /// assets, not a defect in this implementation.
    function test_pre_baseline_artifact_admits_under_v1_and_is_rejected_by_the_v0_vector() public {
        (PQVerdict got, string memory expected) = _runCase(5);
        assertEq(uint256(got), uint256(PQVerdict.Accept), "v1 baseline activates at 0");
        assertEq(_asVerdict(expected) == PQVerdict.Reject, true, "the shipped v0 vector rejects it");
    }

    /// Anchored at 1786500000, after a revocation at 1786000000 and still before the cutoff.
    /// Refused, because ending authority is a stronger signal than the cutoff. An earlier revision
    /// of this file asserted the opposite by reading the cutoff clause in isolation, which was
    /// wrong: resolution runs first.
    function test_post_revocation_artifact_is_refused_even_before_the_cutoff() public {
        (PQVerdict got, string memory expected) = _runCase(7);
        assertEq(uint256(got), uint256(PQVerdict.Reject), "revocation outranks the cutoff");
        assertEq(uint256(_asVerdict(expected)), uint256(PQVerdict.Reject), "the vector agrees");
    }
}
