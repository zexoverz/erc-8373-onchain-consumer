# ERC-8373 on-chain consumer

An on-chain implementation of the consumer half of [ERC-8373](https://github.com/ethereum/ERCs/pull/1932),
Post-Quantum Anchored Key-Binding.

ERC-8373 says that "deployment of the consumer rule, not publication of bindings, is what makes the
migration operative". The proposal specifies the binding statement, the anchoring rules and the
verification procedure, and ships conformance vectors and Python checkers. It does not define an
on-chain surface for any of it. This repository is that surface, plus tests.

## What is here

| File | Role |
|---|---|
| `src/IPQKeyBindingConsumer.sol` | `PQVerdict` tri-state, anchor registry, companion verifier, consumer interface |
| `src/PQCutoffEnforcer.sol` | Reference enforcer: binding chain, rotation, revocation, the cutoff rule |
| `test/PQCutoffEnforcer.t.sol` | 17 behaviour tests |
| `test/CutoffVectors.t.sol` | Drives the enforcer with the published vectors, no mocks for the data |
| `vectors/` | The four published suites, taken from `TMerlini/ERCs` at `5d77b0a9` |

## Two findings

**The published cutoff vectors disagree with the specification text.** Reported on the discussion thread; TMerlini confirmed it and sharpened the diagnosis.

`no_in_force_binding` is doing double duty in the shipped v0 assets, over two cases that deserve opposite answers:

| Case | Correct answer | v0 vector |
|---|---|---|
| pre-baseline, anchored before the first binding was registered | admit classical-only, it is innocent back catalogue | `REJECT` |
| post-revocation, anchored after authority was deliberately ended | reject even pre-cutoff, revocation outranks the cutoff | `REJECT` |

The v1 profile fixes the first by activating the baseline at 0, so it governs from creation. This
enforcer implements v1. It reproduces seven of the eight published vectors and disagrees only on
the pre-baseline case, which is the half the ERC's shipped assets have not caught up with.

Resolution runs before the cutoff, not after. An earlier revision here had that order backwards and
admitted a post-revocation artifact because it fell on the classical-only side. That was wrong:
ending authority is a stronger signal than a consumer's cutoff.

**Anchor time must be read, never passed.** ERC-8373 rests on the asymmetry that a compromised key
can backdate a signature but cannot backdate an anchor. That holds only while the consumer reads
anchor time from the substrate. A consumer taking `anchorTime` as a parameter restores the
backdating it exists to remove, and still passes every published vector, because the vectors do not
model a lying caller. `verifyArtifact` therefore takes no timestamp.

## Scope

The cutoff rule is enforceable on-chain today. The companion signature check is not: ML-DSA is
lattice arithmetic and SLH-DSA is thousands of hash invocations, and neither has an EVM precompile.
`IPQCompanionVerifier` is a separate swappable component so a deployment enforces what it can and
names what it delegates.

## Safety

Not audited. Reference code written to pin the semantics of a draft proposal, not to hold value. The
PQ side of proof-of-possession, the genesis self-signature and the predecessor dual-signature on
rotation, is delegated rather than verified here. Do not deploy this as-is.

## Run

```
forge test
```
