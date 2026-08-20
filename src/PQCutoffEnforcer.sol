// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {
    IPQKeyBindingConsumer,
    IPQAnchorRegistry,
    IPQCompanionVerifier,
    PQDecision,
    PQEvidence
} from "./IPQKeyBindingConsumer.sol";

/// @title A reference ERC-8373 cutoff enforcer
/// @notice Implements the consumer half of the ERC-8373 verification procedure on-chain: read the
///         anchor time from the substrate, apply the cutoff, resolve the in-force binding from the
///         anchored chain, and delegate the companion check.
/// @dev    Reference implementation. Not audited, not gas-tuned, and deliberately readable rather
///         than clever, because its job is to pin the semantics of the rule.
contract PQCutoffEnforcer is IPQKeyBindingConsumer {
    struct Binding {
        bytes32 contentAddress;
        bytes32 predecessor; // bytes32(0) for the genesis binding
        uint64 anchorTime; // read from the substrate, never supplied
        uint64 activatedAt; // 0 for the baseline, anchorTime for every successor
        uint64 revokedAt; // 0 while live
        bool terminal;
        bytes pqPubkey;
    }

    uint64 public immutable override cutoff;
    IPQAnchorRegistry public immutable override anchorRegistry;
    IPQCompanionVerifier public immutable companionVerifier;

    /// @notice The classical address whose transactions anchor this identity's bindings.
    address public immutable classicalAddress;

    Binding[] private _chain;
    mapping(bytes32 => uint256) private _indexPlusOne;

    error NotAnchored(bytes32 contentAddress);
    error WrongAnchorer(address expected, address actual);
    error AlreadyRegistered(bytes32 contentAddress);
    error UnknownBinding(bytes32 contentAddress);
    error PredecessorNotInChain(bytes32 predecessor);
    error ChainIsTerminal();
    error RotationNotForward(uint64 predecessorAnchor, uint64 anchorTime);

    constructor(
        uint64 cutoff_,
        IPQAnchorRegistry anchorRegistry_,
        IPQCompanionVerifier companionVerifier_,
        address classicalAddress_
    ) {
        cutoff = cutoff_;
        anchorRegistry = anchorRegistry_;
        companionVerifier = companionVerifier_;
        classicalAddress = classicalAddress_;
    }

    // ── Chain construction ───────────────────────────────────────────────────

    /// @notice Admit an anchored binding into the chain.
    /// @dev    Everything here is checked against the substrate rather than taken from the caller.
    ///         The anchoring transaction is the classical proof-of-possession, so a binding whose
    ///         anchoring transaction came from any other address is not this identity's binding,
    ///         no matter who submits it here.
    ///
    ///         The PQ side of proof-of-possession (genesis self-signature, and the predecessor's
    ///         dual-signature on rotation) is not verifiable in the EVM today. It is delegated,
    ///         like the companion check, rather than silently assumed.
    function registerBinding(bytes32 contentAddress, bytes32 predecessor, bytes calldata pqPubkey) external {
        if (_indexPlusOne[contentAddress] != 0) revert AlreadyRegistered(contentAddress);

        uint64 anchorTime = anchorRegistry.anchorTimeOf(contentAddress);
        if (anchorTime == 0) revert NotAnchored(contentAddress);

        address anchorer = anchorRegistry.anchoredBy(contentAddress);
        if (anchorer != classicalAddress) revert WrongAnchorer(classicalAddress, anchorer);

        if (_chain.length != 0) {
            uint256 pi = _indexPlusOne[predecessor];
            if (pi == 0) revert PredecessorNotInChain(predecessor);
            Binding storage p = _chain[pi - 1];
            if (p.terminal) revert ChainIsTerminal();
            // Rotation is forward-acting, so a successor cannot claim an earlier anchor than the
            // binding it replaces. Without this, a late-registered but early-anchored statement
            // could be inserted behind an existing one and change history.
            if (anchorTime <= p.anchorTime) revert RotationNotForward(p.anchorTime, anchorTime);
        }

        // v1 profile: the baseline governs from creation, because anchoring gives a binding a
        // provable time rather than a birthday. Successors keep activatedAt = anchor, so a
        // rotation still cannot claim retroactive coverage.
        uint64 activatedAt = _chain.length == 0 ? 0 : anchorTime;

        _chain.push(
            Binding({
                contentAddress: contentAddress,
                predecessor: predecessor,
                anchorTime: anchorTime,
                activatedAt: activatedAt,
                revokedAt: 0,
                terminal: false,
                pqPubkey: pqPubkey
            })
        );
        _indexPlusOne[contentAddress] = _chain.length;
    }

    /// @notice Record an anchored revocation.
    /// @dev    Authority ends at the revocation record's own anchor time, never at a self-declared
    ///         time and never retroactively.
    function revokeBinding(bytes32 contentAddress, bytes32 revocationRecord) external {
        uint256 i = _indexPlusOne[contentAddress];
        if (i == 0) revert UnknownBinding(contentAddress);

        uint64 revokedAt = anchorRegistry.anchorTimeOf(revocationRecord);
        if (revokedAt == 0) revert NotAnchored(revocationRecord);

        address anchorer = anchorRegistry.anchoredBy(revocationRecord);
        if (anchorer != classicalAddress) revert WrongAnchorer(classicalAddress, anchorer);

        _chain[i - 1].revokedAt = revokedAt;
    }

    /// @notice Mark a binding terminal, closing the chain to further rotation.
    function markTerminal(bytes32 contentAddress) external {
        uint256 i = _indexPlusOne[contentAddress];
        if (i == 0) revert UnknownBinding(contentAddress);
        _chain[i - 1].terminal = true;
    }

    // ── Resolution ───────────────────────────────────────────────────────────

    /// @inheritdoc IPQKeyBindingConsumer
    /// @dev The in-force binding at an instant is the latest one ACTIVE at or before it that has
    ///      not been revoked by then.
    ///
    ///      Two cases the reason string must not merge, which is the defect the published v0
    ///      vectors carry:
    ///
    ///      - **pre-baseline**, anchored before the first binding was registered. Innocent back
    ///        catalogue. The baseline activates at 0 and governs from creation, so this resolves
    ///        rather than falling through, and the cutoff then admits it classical-only.
    ///      - **post-revocation**, anchored after a binding's authority was deliberately ended.
    ///        A revocation is a trust-ending act and its signal is stronger than the consumer's
    ///        cutoff, so this resolves to nothing and is refused even before the cutoff.
    ///
    ///      Authority never reverts to a predecessor. That would resurrect something the owner
    ///      retired.
    function inForceBindingAt(uint64 anchorTime) public view override returns (bytes32) {
        uint256 n = _chain.length;
        for (uint256 i = n; i > 0; i--) {
            Binding storage b = _chain[i - 1];
            if (b.activatedAt > anchorTime) continue;
            if (b.revokedAt != 0 && b.revokedAt <= anchorTime) return bytes32(0);
            return b.contentAddress;
        }
        return bytes32(0);
    }

    function pqPubkeyOf(bytes32 contentAddress) public view returns (bytes memory) {
        uint256 i = _indexPlusOne[contentAddress];
        if (i == 0) revert UnknownBinding(contentAddress);
        return _chain[i - 1].pqPubkey;
    }

    function chainLength() external view returns (uint256) {
        return _chain.length;
    }

    // ── The rule ─────────────────────────────────────────────────────────────

    /// @inheritdoc IPQKeyBindingConsumer
    function verifyArtifact(bytes32 artifactContentAddress, bytes calldata companion)
        public
        view
        override
        returns (PQDecision, PQEvidence)
    {
        uint64 anchorTime = anchorRegistry.anchorTimeOf(artifactContentAddress);

        // An artifact whose anchor cannot be read is refused, but the evidence says we could not
        // tell rather than that it was bad. Merging those would let an indexing gap read as a
        // policy decision.
        if (anchorTime == 0) return (PQDecision.Refuse, PQEvidence.Unverifiable);

        // Resolution runs BEFORE the cutoff. A revocation ends authority at its anchor time and
        // that signal outranks the consumer's cutoff, so a post-revocation artifact is refused
        // even when it falls on the classical-only side.
        bytes32 binding = inForceBindingAt(anchorTime);
        if (binding == bytes32(0)) return (PQDecision.Refuse, PQEvidence.Refuted);

        // "proven anchored before the consumer's cutoff". Strictly before.
        if (anchorTime < cutoff) return (PQDecision.Admit, PQEvidence.Verified);

        if (companion.length == 0) return (PQDecision.Refuse, PQEvidence.Refuted);

        bytes memory pqPubkey = _chain[_indexPlusOne[binding] - 1].pqPubkey;

        // A verifier that cannot answer leaves the artifact unchecked. The gate still closes, but
        // the evidence records that nothing was refuted, only that nothing was established.
        try companionVerifier.verifyCompanion(artifactContentAddress, pqPubkey, companion) returns (bool ok) {
            return ok ? (PQDecision.Admit, PQEvidence.Verified) : (PQDecision.Refuse, PQEvidence.Refuted);
        } catch {
            return (PQDecision.Refuse, PQEvidence.Unverifiable);
        }
    }

    /// @notice Verify and emit, so a refusal leaves a trace rather than vanishing.
    function settleArtifact(bytes32 artifactContentAddress, bytes calldata companion)
        external
        returns (PQDecision decision, PQEvidence evidence)
    {
        (decision, evidence) = verifyArtifact(artifactContentAddress, companion);
        uint64 anchorTime = anchorRegistry.anchorTimeOf(artifactContentAddress);
        emit ArtifactSettled(artifactContentAddress, inForceBindingAt(anchorTime), decision, evidence, anchorTime);
    }

    // ── ERC-165 ──────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IPQKeyBindingConsumer).interfaceId || interfaceId == 0x01ffc9a7;
    }
}
