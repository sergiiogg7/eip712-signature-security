# CLAUDE.md

Educational security repo about off-chain signatures. Takes precedence over the parent folder `CLAUDE.md`.

## Commands

```bash
forge build && forge test                    # 56 tests
FOUNDRY_PROFILE=ci forge test                # exhaustive fuzz and invariants
forge fmt --check
forge coverage --no-match-coverage "script|test" --report summary
forge snapshot --check                       # run `forge snapshot` after intentional gas changes
slither . --exclude-dependencies --config-file slither.config.json --fail-low   # needs a venv, not installed globally
cd client && npm install && npm run typecheck
```

## Architecture

- `src/vulnerable/`: four contracts that are broken ON PURPOSE. Do not "fix" them; each one demonstrates one bug and has an exploit test.
- `src/secure/SignatureAuthorizer.sol`: the correct design (EIP-712, nonces, deadline, `SignatureChecker`, `Ownable2Step`).
- `test/mocks/MockERC1271Wallet.sol`: minimal smart-contract wallet.
- `client/src/demo.ts`: viem script; its EIP-712 domain and types must match the contract exactly.

## Tests

`VulnerableAttacks.t.sol` (exploits, named `test_Exploit_*`), `SignatureAuthorizer.t.sol` (unit and `test_Attack_*`), `...Fuzz.t.sol`, `...Invariant.t.sol` (handler with ghost variables). Naming: `test_`, `test_RevertWhen_`, `testFuzz_`, `invariant_`.

## Conventions

- Never describe the vulnerable contracts as safe, and never claim an audit.
- Slither silences are inline, with the reason. No global detector exclusion.
- No commit or push without the owner's approval. No `Co-Authored-By` lines.
- Anvil keys in `LocalDeploy.s.sol` and `demo.ts` are public development keys; real keys only in `.env` (ignored).
