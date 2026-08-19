// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

/// @title The on-chain half of ERC-8373 (Post-Quantum Anchored Key-Binding)
/// @notice ERC-8373 states that "deployment of the consumer rule, not publication of bindings, is
///         what makes the migration operative". These interfaces give that consumer rule a shape a
///         contract can implement and an integrator can detect.
/// @dev    ERC-8373 defines the binding statement, the anchoring rules and the verification
///         procedure. It does not define an on-chain surface for any of it. Everything here is the
///         consumer side of that specification, expressed so that whether a given deployment
///         actually enforces the cutoff is a readable on-chain fact rather than a claim.

// ── Outcome ──────────────────────────────────────────────────────────────────

/// @notice The tri-state outcome of the ERC-8373 verification procedure.
/// @dev    The ERC is explicit that a verifier which cannot complete a step MUST report the
///         artifact unverifiable, "distinct from both accept and reject". Collapsing that into a
///         bool is the single most likely way for an integrator to get this wrong, because the
///         natural bool is `accepted`, and `false` then silently merges "we refused this" with "we
///         could not tell".
///
///         `Unverifiable` is deliberately the zero value. A storage slot that was never written,
///         a failed decode and a struct default all read as "we could not tell", never as accept.
enum PQVerdict {
    Unverifiable, // 0 — a step could not be completed. Never treat as authorization.
    Accept, // 1 — anchored before the cutoff, or carries a valid in-force companion.
    Reject // 2 — anchored at or after the cutoff with no valid in-force companion.
}

// ── Anchor substrate ─────────────────────────────────────────────────────────

/// @notice The anchor substrate, read-side.
/// @dev    ERC-8373 rests its whole guarantee on one asymmetry: "a compromised key can backdate a
///         signature; it cannot backdate an anchor." That holds only while anchor time is *read*
///         from the substrate. A consumer that accepts `anchorTime` as a call parameter hands the
///         caller the backdating power the design exists to remove, and it will still pass every
///         off-chain conformance vector, because the vectors never model a lying caller.
///
///         This is why `IPQKeyBindingConsumer` takes no timestamp from its caller.
interface IPQAnchorRegistry {
    /// @notice The substrate timestamp at which `contentAddress` was anchored.
    /// @return anchorTime unix seconds, or 0 if this content-address was never anchored.
    function anchorTimeOf(bytes32 contentAddress) external view returns (uint64 anchorTime);

    /// @notice The account whose transaction anchored `contentAddress`.
    /// @dev    ERC-8373 makes the anchoring transaction itself the classical proof-of-possession:
    ///         it "MUST be sent from the classical address being bound", and no separate classical
    ///         signature "should be trusted in its place". Exposing the anchoring sender is what
    ///         lets a verifier check that rule on-chain instead of assuming it.
    function anchoredBy(bytes32 contentAddress) external view returns (address anchorer);
}

// ── Companion verification ───────────────────────────────────────────────────

/// @notice Verification of a detached PQ companion signature.
/// @dev    Kept as a separate, swappable component on purpose. ML-DSA and SLH-DSA verification is
///         not practical in the EVM today: SLH-DSA is thousands of hash invocations and ML-DSA is
///         lattice arithmetic, neither of which has a precompile. So the honest position is that
///         **the cutoff rule is enforceable on-chain today and the companion check is not**.
///
///         Splitting them means a consumer can enforce everything it actually can, and name what
///         it delegates, rather than pretending to a completeness it does not have. A deployment
///         may point this at a ZK proof of companion validity, at an attested oracle, or at a
///         precompile if one ever lands, without touching the consumer.
interface IPQCompanionVerifier {
    /// @notice The PQ algorithm this verifier accepts, as the ERC-8373 `algorithm` field
    ///         (for example "ML-DSA-65" or "SLH-DSA-SHA2-192s").
    function algorithm() external view returns (string memory);

    /// @notice Verify a detached companion over an artifact's 32-byte content-address.
    /// @dev    MUST return false rather than revert on a malformed companion, so that a bad
    ///         signature is a reject and only an unavailable verifier is unverifiable.
    function verifyCompanion(bytes32 artifactContentAddress, bytes calldata pqPubkey, bytes calldata companion)
        external
        view
        returns (bool);
}

// ── The consumer rule ────────────────────────────────────────────────────────

/// @notice A contract that enforces the ERC-8373 cutoff.
/// @dev    ERC-165 interface id is the XOR of this interface's own function selectors.
interface IPQKeyBindingConsumer {
    /// @notice The consumer's cutoff, in unix seconds.
    /// @dev    ERC-8373: "The cutoff is consumer-side policy, not issuer-declared." Making it a
    ///         public read is what turns "this deployment enforces the migration" into something a
    ///         counterparty can check before relying on it.
    function cutoff() external view returns (uint64);

    /// @notice The anchor substrate this consumer reads anchor times from.
    function anchorRegistry() external view returns (IPQAnchorRegistry);

    /// @notice The verdict for an artifact, following the ERC-8373 verification procedure.
    /// @param artifactContentAddress the artifact's 32-byte content-address, recomputed by the
    ///        caller from raw bytes as the ERC requires
    /// @param companion a detached PQ companion over that content-address; MAY be empty for an
    ///        artifact expected to fall before the cutoff
    /// @dev   Takes no anchor time. See `IPQAnchorRegistry`.
    ///
    ///        MUST NOT revert on a well-formed-but-failing artifact: a refusal is `Reject` and an
    ///        incomplete check is `Unverifiable`, both of which the caller needs to be able to
    ///        distinguish and act on.
    function verifyArtifact(bytes32 artifactContentAddress, bytes calldata companion) external view returns (PQVerdict);

    /// @notice The binding governing artifacts anchored at `anchorTime`, resolved from the chain.
    /// @dev    ERC-8373: "Resolution MUST run from the chain even at length one." Rotations are
    ///         forward-acting and revocations end authority at their own anchor time, so this is a
    ///         function of the queried instant and not of the present.
    /// @return bindingContentAddress the in-force binding, or bytes32(0) if none is in force
    function inForceBindingAt(uint64 anchorTime) external view returns (bytes32 bindingContentAddress);

    /// @notice Emitted when a consumer settles an artifact, including on refusal.
    /// @dev    Emitted for every outcome, not just acceptance. An artifact that was checked and
    ///         refused must be distinguishable from one that was never presented, which is the
    ///         same asymmetry ERC-8373 removes off-chain by insisting unverifiable is its own
    ///         state.
    event ArtifactSettled(
        bytes32 indexed artifactContentAddress, bytes32 indexed inForceBinding, PQVerdict verdict, uint64 anchorTime
    );
}
