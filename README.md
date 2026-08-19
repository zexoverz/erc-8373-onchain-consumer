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

**The published cutoff vectors disagree with the specification text in two of eight cases.**

ERC-8373's verification procedure, step 3, is "If anchor time < cutoff: verify classically; accept",
and it does not consult the binding chain. Two vectors expect `REJECT` for artifacts anchored before
the cutoff, on the ground that no binding was in force at that instant.

| Case | Anchor time | Cutoff | Spec text | Published vector |
|---|---|---|---|---|
| artifact anchored before any binding existed | 1785000000 | 1790000000 | accept | `REJECT` |
| artifact anchored at/after revocation | 1786500000 | 1790000000 | accept | `REJECT` |

Under the vector reading, a revocation retroactively invalidates artifacts that were anchored before
the cutoff. The proposal's own introduction states the opposite: "the back catalog is never
retroactively invalidated". The enforcer here follows the specification text, and the two cases are
asserted separately so that changing either side makes a test fail.

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
