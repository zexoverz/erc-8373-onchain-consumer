// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PQCutoffEnforcer} from "../src/PQCutoffEnforcer.sol";
import {
    IPQAnchorRegistry,
    IPQCompanionVerifier,
    IPQKeyBindingConsumer,
    PQVerdict
} from "../src/IPQKeyBindingConsumer.sol";

contract MockAnchorRegistry is IPQAnchorRegistry {
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

contract MockCompanionVerifier is IPQCompanionVerifier {
    bool public answer = true;
    bool public shouldRevert;

    function set(bool a, bool r) external {
        answer = a;
        shouldRevert = r;
    }

    function algorithm() external pure returns (string memory) {
        return "ML-DSA-65";
    }

    function verifyCompanion(bytes32, bytes calldata, bytes calldata) external view returns (bool) {
        require(!shouldRevert, "verifier down");
        return answer;
    }
}

contract PQCutoffEnforcerTest is Test {
    uint64 constant CUTOFF = 1_800_000_000;
    address constant CLASSICAL = address(0xC1a551ca1);
    address constant IMPOSTOR = address(0xBAD);

    bytes32 constant GENESIS = keccak256("binding-genesis");
    bytes32 constant ROTATED = keccak256("binding-rotated");
    bytes32 constant REVOKE_REC = keccak256("revocation-record");
    bytes constant PK1 = hex"a1a1";
    bytes constant PK2 = hex"b2b2";
    bytes constant COMPANION = hex"5165";

    MockAnchorRegistry reg;
    MockCompanionVerifier ver;
    PQCutoffEnforcer enf;

    function setUp() public {
        reg = new MockAnchorRegistry();
        ver = new MockCompanionVerifier();
        enf = new PQCutoffEnforcer(CUTOFF, reg, ver, CLASSICAL);

        reg.anchor(GENESIS, CUTOFF - 1000, CLASSICAL);
        enf.registerBinding(GENESIS, bytes32(0), PK1);
    }

    function _artifact(bytes32 id, uint64 t) internal returns (bytes32) {
        reg.anchor(id, t, CLASSICAL);
        return id;
    }

    // ── The cutoff boundary ──────────────────────────────────────────────────
    // ERC-8373 says an artifact is admitted classical-only if it is "proven anchored before the
    // consumer's cutoff". Before is strictly before. These three tests pin that, because an
    // off-by-one here is the difference between a migration that closes and one that does not.

    function test_one_second_before_the_cutoff_is_accepted_without_a_companion() public {
        bytes32 a = _artifact(keccak256("early"), CUTOFF - 1);
        assertEq(uint256(enf.verifyArtifact(a, "")), uint256(PQVerdict.Accept));
    }

    function test_exactly_at_the_cutoff_is_not_admitted_classical_only() public {
        bytes32 a = _artifact(keccak256("at"), CUTOFF);
        assertEq(
            uint256(enf.verifyArtifact(a, "")),
            uint256(PQVerdict.Reject),
            "the cutoff instant is on the far side of the cutoff"
        );
    }

    function test_exactly_at_the_cutoff_is_accepted_with_a_valid_companion() public {
        bytes32 a = _artifact(keccak256("at2"), CUTOFF);
        assertEq(uint256(enf.verifyArtifact(a, COMPANION)), uint256(PQVerdict.Accept));
    }

    // ── The tri-state ────────────────────────────────────────────────────────

    /// Unverifiable must be the zero value, so an unwritten slot or a failed decode can never be
    /// mistaken for authorization.
    function test_unverifiable_is_the_zero_verdict() public pure {
        assertEq(uint256(PQVerdict.Unverifiable), 0);
    }

    /// An artifact nobody anchored is unknown, not refused. Refusing would let an indexing gap
    /// read as a policy decision.
    function test_unanchored_artifact_is_unverifiable_not_rejected() public view {
        assertEq(uint256(enf.verifyArtifact(keccak256("never-anchored"), COMPANION)), uint256(PQVerdict.Unverifiable));
    }

    /// A verifier that cannot answer leaves the artifact unverifiable. A reverting dependency is
    /// not evidence that the artifact is bad.
    function test_failing_companion_verifier_is_unverifiable_not_rejected() public {
        bytes32 a = _artifact(keccak256("late"), CUTOFF + 10);
        ver.set(true, true);
        assertEq(uint256(enf.verifyArtifact(a, COMPANION)), uint256(PQVerdict.Unverifiable));
    }

    /// A companion that is simply wrong is a reject, which must stay distinct from the above.
    function test_invalid_companion_is_rejected() public {
        bytes32 a = _artifact(keccak256("late2"), CUTOFF + 10);
        ver.set(false, false);
        assertEq(uint256(enf.verifyArtifact(a, COMPANION)), uint256(PQVerdict.Reject));
    }

    /// The omission attack the ERC exists to close: after the cutoff, no companion is a reject.
    function test_omitted_companion_after_the_cutoff_fails_closed() public {
        bytes32 a = _artifact(keccak256("late3"), CUTOFF + 10);
        assertEq(uint256(enf.verifyArtifact(a, "")), uint256(PQVerdict.Reject));
    }

    // ── Anchor time is read, never supplied ──────────────────────────────────

    /// The whole design rests on anchor time being unforgeable by the caller. The interface takes
    /// no timestamp, so this test states the property the signature enforces: two callers asking
    /// about the same artifact get the same verdict, and neither can move it across the cutoff.
    function test_callers_cannot_move_an_artifact_across_the_cutoff() public {
        bytes32 a = _artifact(keccak256("fixed"), CUTOFF + 5);
        vm.prank(IMPOSTOR);
        PQVerdict asImpostor = enf.verifyArtifact(a, "");
        vm.prank(CLASSICAL);
        PQVerdict asOwner = enf.verifyArtifact(a, "");
        assertEq(uint256(asImpostor), uint256(asOwner));
        assertEq(uint256(asOwner), uint256(PQVerdict.Reject));
    }

    // ── Proof of possession comes from the anchoring transaction ─────────────

    /// ERC-8373 makes the anchoring transaction the classical proof-of-possession, so a binding
    /// anchored by anyone else is not this identity's binding regardless of who registers it.
    function test_binding_anchored_by_another_address_is_refused() public {
        bytes32 b = keccak256("impostor-binding");
        reg.anchor(b, CUTOFF - 500, IMPOSTOR);
        vm.expectRevert(abi.encodeWithSelector(PQCutoffEnforcer.WrongAnchorer.selector, CLASSICAL, IMPOSTOR));
        enf.registerBinding(b, GENESIS, PK2);
    }

    function test_unanchored_binding_cannot_be_registered() public {
        vm.expectRevert(abi.encodeWithSelector(PQCutoffEnforcer.NotAnchored.selector, keccak256("ghost")));
        enf.registerBinding(keccak256("ghost"), GENESIS, PK2);
    }

    // ── Rotation is forward-acting ───────────────────────────────────────────

    /// Artifacts anchored before a rotation keep resolving to the predecessor.
    function test_rotation_does_not_reach_backwards() public {
        reg.anchor(ROTATED, CUTOFF + 100, CLASSICAL);
        enf.registerBinding(ROTATED, GENESIS, PK2);

        assertEq(enf.inForceBindingAt(CUTOFF + 50), GENESIS, "before the rotation");
        assertEq(enf.inForceBindingAt(CUTOFF + 100), ROTATED, "at the rotation");
        assertEq(enf.inForceBindingAt(CUTOFF + 500), ROTATED, "after the rotation");
    }

    /// A successor cannot be inserted behind its predecessor. Without this, a late-registered but
    /// early-anchored statement could rewrite which key governed a past instant.
    function test_successor_cannot_claim_an_earlier_anchor_than_its_predecessor() public {
        bytes32 backdated = keccak256("backdated-rotation");
        reg.anchor(backdated, CUTOFF - 2000, CLASSICAL);
        vm.expectRevert(
            abi.encodeWithSelector(PQCutoffEnforcer.RotationNotForward.selector, CUTOFF - 1000, CUTOFF - 2000)
        );
        enf.registerBinding(backdated, GENESIS, PK2);
    }

    // ── Revocation ends authority at its own anchor time ─────────────────────

    function test_revocation_is_not_retroactive() public {
        reg.anchor(REVOKE_REC, CUTOFF + 200, CLASSICAL);
        enf.revokeBinding(GENESIS, REVOKE_REC);

        assertEq(enf.inForceBindingAt(CUTOFF + 199), GENESIS, "earlier artifacts remain governed");
        assertEq(enf.inForceBindingAt(CUTOFF + 200), bytes32(0), "authority ends at the anchor");
        assertEq(enf.inForceBindingAt(CUTOFF + 999), bytes32(0));
    }

    /// An artifact anchored after a revocation, with no live binding, is refused rather than
    /// admitted. Documents the fail-closed reading of a point the ERC leaves open: whether a
    /// revoked binding falls back to its predecessor. This asserts that it does not.
    function test_artifact_after_revocation_is_rejected_with_no_fallback() public {
        reg.anchor(REVOKE_REC, CUTOFF + 200, CLASSICAL);
        enf.revokeBinding(GENESIS, REVOKE_REC);
        bytes32 a = _artifact(keccak256("post-revocation"), CUTOFF + 300);
        assertEq(uint256(enf.verifyArtifact(a, COMPANION)), uint256(PQVerdict.Reject));
    }

    // ── Detectability ────────────────────────────────────────────────────────

    /// The ERC says deployment of the consumer rule is what makes the migration operative, so a
    /// counterparty has to be able to tell that a given contract enforces it, and read the cutoff
    /// it enforces, before relying on it.
    function test_consumer_is_detectable_and_its_cutoff_is_readable() public view {
        assertTrue(enf.supportsInterface(type(IPQKeyBindingConsumer).interfaceId));
        assertTrue(enf.supportsInterface(0x01ffc9a7));
        assertFalse(enf.supportsInterface(0xffffffff));
        assertEq(enf.cutoff(), CUTOFF);
    }

    function test_settle_emits_on_refusal_too() public {
        bytes32 a = _artifact(keccak256("refused"), CUTOFF + 10);
        vm.recordLogs();
        enf.settleArtifact(a, "");
        assertEq(vm.getRecordedLogs().length, 1, "a refusal must leave a trace");
    }
}
