// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IPQKeyBindingConsumer, IPQAnchorRegistry, IPQCompanionVerifier, PQVerdict} from "./IPQKeyBindingConsumer.sol";

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

        _chain.push(
            Binding({
                contentAddress: contentAddress,
                predecessor: predecessor,
                anchorTime: anchorTime,
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
    /// @dev The in-force binding at an instant is the latest one anchored at or before it that has
    ///      not been revoked by then. Revocation does not fall back to the predecessor: a revoked
    ///      binding leaves nothing in force for that instant. That reading is fail-closed, but the
    ///      ERC does not state it either way, and it is worth the authors settling explicitly.
    function inForceBindingAt(uint64 anchorTime) public view override returns (bytes32) {
        uint256 n = _chain.length;
        for (uint256 i = n; i > 0; i--) {
            Binding storage b = _chain[i - 1];
            if (b.anchorTime > anchorTime) continue;
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
        returns (PQVerdict)
    {
        uint64 anchorTime = anchorRegistry.anchorTimeOf(artifactContentAddress);

        // An artifact whose anchor cannot be read is not refused, it is unknown. Refusing here
        // would let an indexing gap read as a policy decision.
        if (anchorTime == 0) return PQVerdict.Unverifiable;

        // "proven anchored before the consumer's cutoff". Strictly before: an artifact anchored at
        // exactly the cutoff instant is on the far side of it and owes a companion.
        if (anchorTime < cutoff) return PQVerdict.Accept;

        bytes32 binding = inForceBindingAt(anchorTime);
        if (binding == bytes32(0)) return PQVerdict.Reject;

        if (companion.length == 0) return PQVerdict.Reject;

        bytes memory pqPubkey = _chain[_indexPlusOne[binding] - 1].pqPubkey;

        // A verifier that cannot answer leaves the artifact unverifiable rather than refused.
        try companionVerifier.verifyCompanion(artifactContentAddress, pqPubkey, companion) returns (bool ok) {
            return ok ? PQVerdict.Accept : PQVerdict.Reject;
        } catch {
            return PQVerdict.Unverifiable;
        }
    }

    /// @notice Verify and emit, so a refusal leaves a trace rather than vanishing.
    function settleArtifact(bytes32 artifactContentAddress, bytes calldata companion)
        external
        returns (PQVerdict verdict)
    {
        verdict = verifyArtifact(artifactContentAddress, companion);
        uint64 anchorTime = anchorRegistry.anchorTimeOf(artifactContentAddress);
        emit ArtifactSettled(artifactContentAddress, inForceBindingAt(anchorTime), verdict, anchorTime);
    }

    // ── ERC-165 ──────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IPQKeyBindingConsumer).interfaceId || interfaceId == 0x01ffc9a7;
    }
}
