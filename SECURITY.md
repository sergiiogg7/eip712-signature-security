# Security

## Status

**This project has not been audited by any external party.** It is an educational portfolio project. Do not use it with real funds.

The four contracts in `src/vulnerable/` are **intentionally vulnerable**. They exist to demonstrate exploits and must never be deployed outside a test environment. Only `src/secure/SignatureAuthorizer.sol` is meant to show a correct design.

## Measures in `SignatureAuthorizer`

| Measure | Where | Mitigates |
|---|---|---|
| EIP-712 typed data with domain (name, version, chainId, verifyingContract) | `hashAuthorization`, `EIP712` constructor | Replay on other deployments or chains |
| Per-user nonce inside the signed message, incremented on success | `authorize`, `nonces` | Replay of the same signature, replay after `revoke` |
| Deadline inside the signed message | `authorize` | Signatures valid forever |
| Recovered signer compared with `authorizer` | `SignatureChecker.isValidSignatureNow` | Signing with an arbitrary key |
| OpenZeppelin `ECDSA` via `SignatureChecker` | `authorize` | `address(0)` from `ecrecover`, invalid `v`, high-`s` malleability |
| ERC-1271 fallback for contract authorizers | `SignatureChecker` | Smart-contract wallets cannot sign with ECDSA |
| `Ownable2Step` | contract | Ownership sent to a wrong address |
| Custom errors, zero-address checks | `ZeroAddress`, `InvalidSignature`, `SignatureExpired`, `NotAuthorized` | Silent misconfiguration |

No `ReentrancyGuard` and no `SafeERC20`: the contract moves no ETH or tokens, and its only external call is the `staticcall` of ERC-1271.

## Invariants (tested)

- The sum of all `nonces` equals the number of successful authorizations.
- A replayed signature, or a valid signature from a key that is not the authorizer, never succeeds.
- A user with `authorizedUsers == true` has consumed at least one nonce.

## Design notes and limitations

- **The authorizer is a single point of trust.** If its key leaks, anyone can authorize anyone until the owner calls `setAuthorizer`. Use a multisig or a Safe as authorizer on a real network (that is what ERC-1271 support is for).
- **Anyone can submit a signature.** That is intentional (relayers). Front-running only changes who pays the gas; the effect is the same.
- **An authorizer that is a contract controls its own validity.** If the ERC-1271 wallet is upgradable or rotates signers, previously signed messages follow that logic.
- **Deadlines use `block.timestamp`.** A validator can skew it by seconds, irrelevant for deadlines of minutes. Slither's `timestamp` detector is silenced inline with this reason.
- **Domain separator caching.** OpenZeppelin `EIP712` recomputes the separator if `chainId` changes (hard fork), so signatures from before the fork are rejected.
- The vulnerable contracts use `require` with strings and no custom errors on purpose, to stay close to what is found in real code.

## Tooling

Slither runs in CI with `fail-on: low`. The only silenced findings are `missing-zero-check` in `VulnEcrecoverZero` (it is the bug being demonstrated) and `timestamp` in `authorize` (see above), both inline with a comment.

## Reporting a vulnerability

Use a private GitHub security advisory on this repository. Do not open a public issue for a vulnerability in `SignatureAuthorizer`. Findings in `src/vulnerable/` are known by design.
