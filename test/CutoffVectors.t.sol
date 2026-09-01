// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PQCutoffEnforcer} from "../src/PQCutoffEnforcer.sol";
import {IPQAnchorRegistry, IPQCompanionVerifier, PQDecision, PQEvidence} from "../src/IPQKeyBindingConsumer.sol";
import {VectorChain, VectorBinding, ChainShape} from "./VectorChain.sol";

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
/// @dev Rewritten 1 Sep 2026. The previous runner registered the file's genesis binding for EVERY
///      case regardless of what the case declared, and read only `bindings[0].revoked_at`. Under
///      that runner the suite reported 9 green against a 9-case file. The published file now
///      carries 26 cases and declares a per-case chain on 17 of them, including one that is
///      explicitly unavailable. The old runner could not present any of those, so cases it
///      "passed" were never actually asked. Case 12 is the clearest: it declares `bindings: null`,
///      the runner registered genesis anyway, and the enforcer admitted an artifact the case says
///      is unverifiable.
///
///      This runner builds each case's own chain and fails loudly, naming the missing capability,
///      when the enforcer cannot be driven into the declared state at all. A state the reference
///      implementation cannot represent is a finding, not a case to skip.
contract CutoffVectorsTest is Test {
    using VectorChain for string;

    string constant V1 = "vectors/pq-key-binding-v1.cutoff-vectors.json";
    string constant V0 = "vectors/pq-key-binding-v0.cutoff-vectors.json";

    address constant CLASSICAL = 0xFf9a176577Fb42b6bc9c19fd05a241e8fCd0ca14;

    string json;
    uint64 consumerCutoff;
    uint256 caseCount;

    function setUp() public {
        json = vm.readFile(V1);
        consumerCutoff = uint64(vm.parseJsonUint(json, ".consumer_cutoff"));
        while (vm.keyExistsJson(json, string.concat(_case(caseCount), ".artifact.anchor_time"))) {
            caseCount++;
        }
    }

    function _case(uint256 i) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "]");
    }

    // ── Driving one case ─────────────────────────────────────────────────────

    /// @dev Returns the enforcer with the case's declared chain built, plus `unrepresentable` set
    ///      to the capability the enforcer lacks when the state cannot be reached at all.
    function _build(uint256 i)
        internal
        returns (PQCutoffEnforcer enf, VectorCompanionVerifier ver, string memory unrepresentable)
    {
        VectorAnchorSubstrate sub = new VectorAnchorSubstrate();
        ver = new VectorCompanionVerifier();
        enf = new PQCutoffEnforcer(consumerCutoff, sub, ver, CLASSICAL);

        ChainShape shape = VectorChain.shapeOf(json, i);

        if (shape == ChainShape.Unavailable) {
            // `bindings: null` means the chain could not be fetched. The enforcer has no way to
            // say that: an unloaded chain and a chain that resolves to nothing are the same
            // zero-length array, so it answers Refuted where the case requires Unverifiable.
            return (enf, ver, "chain-unavailable state (bindings:null) is not representable: an unloaded chain is indistinguishable from an empty one");
        }

        if (shape == ChainShape.Empty) {
            return (enf, ver, ""); // an empty chain is exactly a chain with nothing registered
        }

        if (shape == ChainShape.Default) {
            bytes32 ca = keccak256(bytes(vm.parseJsonString(json, ".bindings[0].name")));
            sub.anchor(ca, uint64(vm.parseJsonUint(json, ".bindings[0].binding_anchor_time")), CLASSICAL);
            enf.registerBinding(ca, bytes32(0), bytes(vm.parseJsonString(json, ".bindings[0].pq_pubkey")));
            return (enf, ver, "");
        }

        uint256 n = VectorChain.countOf(json, i);
        bytes32 prev = bytes32(0);
        for (uint256 k = 0; k < n; k++) {
            VectorBinding memory b =
                VectorChain.readAt(json, string.concat(VectorChain.path(i), "[", vm.toString(k), "]"));

            if (!b.anchored) {
                // `binding_anchor_time: null`. registerBinding reads the anchor from the substrate
                // and reverts NotAnchored, so an un-anchored binding cannot enter the chain at all
                // and the case's declared state is unreachable.
                return (enf, ver, string.concat("un-anchored binding '", b.name, "' cannot be registered: registerBinding reverts NotAnchored"));
            }

            if (b.hasActivatedAt && b.activatedAt != (k == 0 ? 0 : b.anchorTime)) {
                // The enforcer derives activatedAt rather than accepting it, so a declared value
                // that disagrees (case 17's retroactive activation) cannot be presented, and the
                // malformed chain it is meant to expose is never seen.
                return (enf, ver, "declared activated_at cannot be presented: the enforcer derives it and has no malformed-chain state");
            }

            bytes32 ca = keccak256(bytes(b.name));
            sub.anchor(ca, b.anchorTime, CLASSICAL);
            enf.registerBinding(ca, prev, b.pqPubkey);
            prev = ca;

            if (b.hasRevokedAt) {
                bytes32 rec = keccak256(abi.encodePacked(b.name, "-revocation"));
                sub.anchor(rec, b.revokedAt, CLASSICAL);
                enf.revokeBinding(ca, rec);
            }
        }
        return (enf, ver, "");
    }

    function _runCase(uint256 i)
        internal
        returns (PQDecision decision, PQEvidence evidence, string memory unrepresentable)
    {
        PQCutoffEnforcer enf;
        VectorCompanionVerifier ver;
        (enf, ver, unrepresentable) = _build(i);
        if (bytes(unrepresentable).length != 0) return (PQDecision.Refuse, PQEvidence.Unverifiable, unrepresentable);

        VectorAnchorSubstrate sub = VectorAnchorSubstrate(address(enf.anchorRegistry()));
        uint64 anchorTime = uint64(vm.parseJsonUint(json, string.concat(_case(i), ".artifact.anchor_time")));
        bytes32 artifact = keccak256(abi.encode("artifact", i));
        sub.anchor(artifact, anchorTime, CLASSICAL);

        bytes memory companion = _configureCompanion(i, ver);
        (decision, evidence) = enf.verifyArtifact(artifact, companion);
    }

    /// Reads the companion block for a case and configures the verifier to match it.
    function _configureCompanion(uint256 i, VectorCompanionVerifier ver) internal returns (bytes memory companion) {
        if (!vm.keyExistsJson(json, string.concat(_case(i), ".artifact.pq_companion.present"))) {
            return companion;
        }
        companion = hex"5165";

        // A vector with no `valid` key is the UNCHECKED case: the companion is present but nothing
        // was established about it. On-chain that is a verifier which cannot answer.
        bool isUnchecked = !vm.keyExistsJson(json, string.concat(_case(i), ".artifact.pq_companion.valid"));
        bool isValid =
            isUnchecked ? false : vm.parseJsonBool(json, string.concat(_case(i), ".artifact.pq_companion.valid"));

        bool inForce = true;
        if (vm.keyExistsJson(json, string.concat(_case(i), ".artifact.pq_companion.pq_pubkey"))) {
            inForce = _startsWith(
                vm.parseJsonString(json, string.concat(_case(i), ".artifact.pq_companion.pq_pubkey")), "638c"
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

    function _expected(uint256 i, string memory field) internal view returns (string memory) {
        return vm.parseJsonString(json, string.concat(_case(i), ".expected.", field));
    }

    // ── The suite ────────────────────────────────────────────────────────────

    /// Assert we are reading the file we think we are, before drawing any conclusion from it.
    function test_v1_vector_file_is_the_published_one() public view {
        assertEq(consumerCutoff, 1790000000);
        assertEq(uint64(vm.parseJsonUint(json, ".bindings[0].binding_anchor_time")), 1785423299);
        assertEq(caseCount, 26, "the published v1 set has 26 cases; a different count means a stale copy");
    }

    /// Every state the file declares must be reachable. A case the enforcer cannot be driven into
    /// is a gap in the enforcer, and silently skipping it is how a suite reports coverage it does
    /// not have.
    function test_every_declared_state_is_representable() public {
        string memory gaps;
        uint256 n;
        for (uint256 i = 0; i < caseCount; i++) {
            (,, string memory why) = _runCase(i);
            if (bytes(why).length != 0) {
                n++;
                gaps = string.concat(gaps, "\n  case ", vm.toString(i), ": ", why);
            }
        }
        assertEq(n, 0, string.concat("states the enforcer cannot represent:", gaps));
    }

    /// Every published case reproduces on the admission decision.
    function test_enforcer_reproduces_every_v1_decision() public {
        for (uint256 i = 0; i < caseCount; i++) {
            (PQDecision got,, string memory why) = _runCase(i);
            if (bytes(why).length != 0) continue; // counted by the representability test
            assertEq(
                uint256(got),
                uint256(_asDecision(_expected(i, "decision"))),
                string.concat("case ", vm.toString(i), " decision")
            );
        }
    }

    /// And on the evidence, which is the field v1 added and which a single verdict cannot carry.
    function test_enforcer_reproduces_every_v1_evidence() public {
        uint256 checked;
        for (uint256 i = 0; i < caseCount; i++) {
            (, PQEvidence got, string memory why) = _runCase(i);
            if (bytes(why).length != 0) continue;
            assertEq(
                uint256(got),
                uint256(_asEvidence(_expected(i, "evidence"))),
                string.concat("case ", vm.toString(i), " evidence")
            );
            checked++;
        }
        assertGt(checked, 0, "no case was actually checked");
    }

    /// The pair that motivated splitting the enum. Both refuse, and they are not the same fact.
    /// Selected by what the case declares rather than by index, because indices move when the
    /// published file grows and a hardcoded one silently checks the wrong case.
    function test_refuted_and_unverifiable_both_refuse_but_stay_distinct() public {
        (uint256 refutedCase, bool foundR) = _firstCaseWithEvidence("refuted");
        (uint256 unvCase, bool foundU) = _firstCaseWithEvidence("unverifiable");
        assertTrue(foundR && foundU, "the file must declare both evidence states");

        (PQDecision dRef, PQEvidence eRef,) = _runCase(refutedCase);
        (PQDecision dUnc, PQEvidence eUnc,) = _runCase(unvCase);

        assertEq(uint256(dRef), uint256(PQDecision.Refuse));
        assertEq(uint256(dUnc), uint256(PQDecision.Refuse));
        assertEq(uint256(eRef), uint256(PQEvidence.Refuted), "checked and failed");
        assertEq(uint256(eUnc), uint256(PQEvidence.Unverifiable), "never checked");
        assertTrue(eRef != eUnc, "a single verdict field would merge these");
    }

    function _firstCaseWithEvidence(string memory want) internal returns (uint256, bool) {
        for (uint256 i = 0; i < caseCount; i++) {
            (,, string memory why) = _runCase(i);
            if (bytes(why).length != 0) continue;
            if (keccak256(bytes(_expected(i, "evidence"))) == keccak256(bytes(want))) return (i, true);
        }
        return (0, false);
    }

    /// The ERC's PR still carries the v0 vectors, which reject a pre-baseline artifact even though
    /// it is anchored before the cutoff. v1 admits it. Both sides are found by their declared
    /// reason rather than by index.
    function test_v0_assets_still_reject_what_v1_admits() public view {
        string memory v0 = vm.readFile(V0);
        assertEq(vm.parseJsonString(v0, ".cases[5].expected.decision"), "REJECT", "v0 rejects it");

        bool found;
        for (uint256 i = 0; i < caseCount && !found; i++) {
            if (keccak256(bytes(_expected(i, "resolution_reason"))) == keccak256("pre_baseline")) {
                assertEq(_expected(i, "decision"), "ADMIT", "v1 admits a pre-baseline artifact");
                found = true;
            }
        }
        assertTrue(found, "v1 must declare a pre_baseline case");
    }
}
