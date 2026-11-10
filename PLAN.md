# Plan

Origin: course workshop `Bloque-19` (ecrecover validation). Project type: educational security case study, no frontend (viem script instead).

| Date | Change |
|---|---|
| 2026-11-10 | Repo created with `forge init`, OpenZeppelin v5.4.0, pinned config, CI and Slither config. Course code copied unchanged: 12 tests green. Finding: the course "secure" version never checks who signed. |
| 2026-11-10 | Rewritten as an attack catalogue: `src/vulnerable/` with 4 contracts (zero-address `ecrecover`, no signer check, malleable replay, replay and no domain). |
| 2026-11-10 | `SignatureAuthorizer`: EIP-712, nonce, deadline, `SignatureChecker` (ECDSA and ERC-1271), `Ownable2Step`. |
| 2026-11-10 | Tests: exploits, unit, fuzz, invariants, ERC-1271 mock. 56 tests, 100 % line coverage, Slither 0 findings. |
| 2026-11-10 | `Deploy` and `LocalDeploy` scripts; viem script (`client/`) verified end to end on Anvil. |

## Pending

- Badges with the CI link once the GitHub repo exists.
- GitHub About (description): "Five real signature bugs in Solidity (ecrecover, malleability, replay) with working exploits, and a secure EIP-712 + ERC-1271 implementation. Foundry + viem."
- GitHub topics: `solidity`, `foundry`, `eip-712`, `erc-1271`, `ecrecover`, `smart-contract-security`, `viem`, `signature-replay`.
- Push, CI check and `gh run list` after the first push.
- Optional: ERC-2612 `permit` token or a meta-transaction relayer extension.
- Optional: deploy to Sepolia and verify on Etherscan.
