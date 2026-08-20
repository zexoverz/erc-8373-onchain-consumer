// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PQCutoffEnforcer} from "../src/PQCutoffEnforcer.sol";
import {IPQAnchorRegistry, IPQCompanionVerifier, PQDecision, PQEvidence} from "../src/IPQKeyBindingConsumer.sol";

/// @notice A substrate replaying the anchor times the vectors record, and nothing else.
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

/// @notice Companion validity as the vectors supply it. The v1 file distinguishes a companion that
///         was CHECKED and failed from one that could not be checked at all, so this models both.
///         `down` reverts, which is how a verifier that cannot answer presents on-chain.
contract VectorCompanionVerifier is IPQCompanionVerifier {
    bool public valid;
    bool public underInForceKey;
    bool public down;

    function set(bool valid_, bool inForce_, bool down_) external {
        valid = valid_;
        underInForceKey = inForce_;
        down = down_;
    }

    function algorithm() external pure returns (string memory) {
        return "SLH-DSA-SHA2-192s";
    }

    function verifyCompanion(bytes32, bytes calldata, bytes calldata) external view returns (bool) {
        require(!down, "verifier unavailable");
        return valid && underInForceKey;
    }
}

/// @notice Drives the reference enforcer with the published ERC-8373 conformance vectors.
///
/// The v1 profile landed in `trustless-ai/recompute-kit` on 20 Aug 2026, after the inconsistency in
/// the v0 assets was reported on the discussion thread. v1 splits `evidence` from `decision`, and
/// this enforcer carries the same split: a companion checked and failed is refuted, one that could
/// not be checked is unverifiable, and both refuse admission.
contract CutoffVectorsTest is Test {
    string constant V1 = "vectors/pq-key-binding-v1.cutoff-vectors.json";
    string constant V0 = "vectors/pq-key-binding-v0.cutoff-vectors.json";
    address constant CLASSICAL = 0xFf9a176577Fb42b6bc9c19fd05a241e8fCd0ca14;

    bytes32 constant GENESIS = keccak256("kya-l4-genesis");
    bytes32 constant REVOKE_REC = keccak256("kya-l4-revocation");

    string json;
    uint64 consumerCutoff;
    uint64 bindingAnchor;
    uint256 caseCount;

    function setUp() public {
        json = vm.readFile(V1);
        consumerCutoff = uint64(vm.parseJsonUint(json, ".consumer_cutoff"));
        bindingAnchor = uint64(vm.parseJsonUint(json, ".bindings[0].binding_anchor_time"));
        while (vm.keyExistsJson(json, string.concat(_path(caseCount), ".artifact.anchor_time"))) {
            caseCount++;
        }
    }

    function _path(uint256 i) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "]");
    }

    function _runCase(uint256 i)
        internal
        returns (PQDecision decision, PQEvidence evidence, string memory expDecision, string memory expEvidence)
    {
        VectorCompanionVerifier ver = new VectorCompanionVerifier();
        VectorAnchorSubstrate sub = new VectorAnchorSubstrate();
        sub.anchor(GENESIS, bindingAnchor, CLASSICAL);
        PQCutoffEnforcer enf = new PQCutoffEnforcer(consumerCutoff, sub, ver, CLASSICAL);
        enf.registerBinding(GENESIS, bytes32(0), hex"638c");

        string memory revPath = string.concat(_path(i), ".bindings[0].revoked_at");
        if (vm.keyExistsJson(json, revPath)) {
            sub.anchor(REVOKE_REC, uint64(vm.parseJsonUint(json, revPath)), CLASSICAL);
            enf.revokeBinding(GENESIS, REVOKE_REC);
        }

        uint64 anchorTime = uint64(vm.parseJsonUint(json, string.concat(_path(i), ".artifact.anchor_time")));
        bytes32 artifact = keccak256(abi.encode("artifact", i));
        sub.anchor(artifact, anchorTime, CLASSICAL);

        bytes memory companion = _configureCompanion(i, ver);

        (decision, evidence) = enf.verifyArtifact(artifact, companion);
        expDecision = vm.parseJsonString(json, string.concat(_path(i), ".expected.decision"));
        string memory evPath = string.concat(_path(i), ".expected.evidence");
        expEvidence = vm.keyExistsJson(json, evPath) ? vm.parseJsonString(json, evPath) : "";
    }

    /// Reads the companion block for a case and configures the verifier to match it.
    /// Split out of `_runCase` to keep that frame under the stack limit.
    function _configureCompanion(uint256 i, VectorCompanionVerifier ver) internal returns (bytes memory companion) {
        if (!vm.keyExistsJson(json, string.concat(_path(i), ".artifact.pq_companion.present"))) {
            return companion;
        }
        companion = hex"5165";

        // A vector with no `valid` key is the UNCHECKED case: the companion is present but nothing
        // was established about it. On-chain that is a verifier which cannot answer.
        bool isUnchecked = !vm.keyExistsJson(json, string.concat(_path(i), ".artifact.pq_companion.valid"));
        bool isValid =
            isUnchecked ? false : vm.parseJsonBool(json, string.concat(_path(i), ".artifact.pq_companion.valid"));

        bool inForce = true;
        if (vm.keyExistsJson(json, string.concat(_path(i), ".artifact.pq_companion.pq_pubkey"))) {
            inForce = _startsWith(
                vm.parseJsonString(json, string.concat(_path(i), ".artifact.pq_companion.pq_pubkey")), "638c"
            );
        }
        ver.set(isValid, inForce, isUnchecked);
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

    function _asDecision(string memory d) internal pure returns (PQDecision) {
        bytes32 h = keccak256(bytes(d));
        return (h == keccak256("ADMIT") || h == keccak256("ACCEPT")) ? PQDecision.Admit : PQDecision.Refuse;
    }

    function _asEvidence(string memory e) internal pure returns (PQEvidence) {
        bytes32 h = keccak256(bytes(e));
        if (h == keccak256("refuted")) return PQEvidence.Refuted;
        if (h == keccak256("unverifiable")) return PQEvidence.Unverifiable;
        return PQEvidence.Verified;
    }

    /// Assert we are reading the file we think we are, before drawing any conclusion from it.
    function test_v1_vector_file_is_the_published_one() public view {
        assertEq(consumerCutoff, 1790000000);
        assertEq(bindingAnchor, 1785423299);
        assertEq(caseCount, 9);
    }

    /// Every published v1 case reproduces on the admission decision.
    function test_enforcer_reproduces_every_v1_decision() public {
        for (uint256 i = 0; i < caseCount; i++) {
            (PQDecision got,, string memory exp,) = _runCase(i);
            assertEq(uint256(got), uint256(_asDecision(exp)), string.concat("case ", vm.toString(i), " decision"));
        }
    }

    /// And on the evidence, which is the field v1 added and which a single verdict cannot carry.
    function test_enforcer_reproduces_every_v1_evidence() public {
        uint256 checked;
        for (uint256 i = 0; i < caseCount; i++) {
            (, PQEvidence got,, string memory exp) = _runCase(i);
            if (bytes(exp).length == 0) continue;
            assertEq(uint256(got), uint256(_asEvidence(exp)), string.concat("case ", vm.toString(i), " evidence"));
            checked++;
        }
        assertGt(checked, 0, "no case declared an evidence field");
    }

    /// The pair that motivated splitting the enum. Both refuse, and they are not the same fact.
    function test_refuted_and_unverifiable_both_refuse_but_stay_distinct() public {
        (PQDecision dRef, PQEvidence eRef,,) = _runCase(3);
        (PQDecision dUnc, PQEvidence eUnc,,) = _runCase(5);

        assertEq(uint256(dRef), uint256(PQDecision.Refuse));
        assertEq(uint256(dUnc), uint256(PQDecision.Refuse));
        assertEq(uint256(eRef), uint256(PQEvidence.Refuted), "checked and failed");
        assertEq(uint256(eUnc), uint256(PQEvidence.Unverifiable), "never checked");
        assertTrue(eRef != eUnc, "a single verdict field would merge these");
    }

    /// The ERC's PR still carries the v0 vectors, which reject a pre-baseline artifact even though
    /// it is anchored before the cutoff. v1 admits it. This reads both files directly so the gap
    /// stays visible until the ERC's assets are advanced.
    function test_v0_assets_still_reject_what_v1_admits() public view {
        string memory v0 = vm.readFile(V0);
        assertEq(vm.parseJsonString(v0, ".cases[5].expected.decision"), "REJECT", "v0 rejects it");
        assertEq(vm.parseJsonString(json, ".cases[6].expected.decision"), "ADMIT", "v1 admits it");
    }
}
