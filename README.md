# Signature Security Workshop

![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636) ![Foundry](https://img.shields.io/badge/Foundry-1.7.1-orange) ![Tests](https://img.shields.io/badge/tests-56-brightgreen)

Off-chain signatures are how contracts delegate authority: whitelists, claims, meta-transactions, permits. They are also where many real exploits start. This repo shows **five classic signature bugs, each with a working exploit**, and a **secure contract that fixes all of them** (EIP-712, nonces, deadline, OpenZeppelin ECDSA, ERC-1271), plus a **viem script** that signs and submits on a local node.

> **Status:** educational project, **not audited**. The contracts in `src/vulnerable/` are insecure on purpose and must never be deployed. See [`SECURITY.md`](SECURITY.md).

## The bugs and the fixes

| # | Bug | Vulnerable contract | What the attacker does | How `SignatureAuthorizer` fixes it |
|---|---|---|---|---|
| 1 | `ecrecover` returns `address(0)` on invalid input and nobody checks it | [`VulnEcrecoverZero`](src/vulnerable/VulnEcrecoverZero.sol) | With `trustedSigner == address(0)`, sends `v=0, r=0, s=0` and is authorized | OpenZeppelin `ECDSA` returns an error instead of `address(0)`; the authorizer can never be zero (`ZeroAddress`) |
| 2 | Valid signature, but nobody checks **who** signed | [`VulnNoSignerCheck`](src/vulnerable/VulnNoSignerCheck.sol) | Signs with their own key and authorizes themselves | The recovered signer must equal `authorizer` |
| 3 | Replay protection keyed by the signature bytes (malleability) | [`VulnMalleableReplay`](src/vulnerable/VulnMalleableReplay.sol) | Flips `s -> n - s` and `v`: second valid signature, credited twice | OpenZeppelin rejects high `s`; replay protection is a **nonce inside the signed message**, not the signature |
| 4 | No nonce / used-signature tracking | [`VulnReplay`](src/vulnerable/VulnReplay.sol) | Submits the same signature forever | Per-user `nonces`, consumed on success |
| 5 | Signed message not bound to contract or chain | [`VulnReplay`](src/vulnerable/VulnReplay.sol) | Reuses a signature on another deployment or another chain | EIP-712 domain separator (`name`, `version`, `chainId`, `verifyingContract`) |

Every exploit is a test in [`test/VulnerableAttacks.t.sol`](test/VulnerableAttacks.t.sol) (names start with `test_Exploit_`). The same attacks are replayed against the secure contract in [`test/SignatureAuthorizer.t.sol`](test/SignatureAuthorizer.t.sol) (`test_Attack_*`) and all fail.

## The secure contract

[`SignatureAuthorizer`](src/secure/SignatureAuthorizer.sol): a trusted `authorizer` signs an EIP-712 message `Authorization(address user, uint256 nonce, uint256 deadline)` off-chain; anyone (a relayer) can submit it and pay the gas.

```text
 authorizer (off-chain)            relayer                     SignatureAuthorizer
       |  sign Authorization(user, nonce, deadline)                    |
       |------------------------> signature                            |
       |                          | authorize(user, deadline, sig) --->|
       |                          |                  1. deadline not passed
       |                          |                  2. digest = EIP-712(domain, user, nonces[user], deadline)
       |                          |                  3. SignatureChecker: signer == authorizer ?
       |                          |                       EOA -> ECDSA   |   contract -> ERC-1271
       |                          |                  4. nonces[user]++ ; authorizedUsers[user] = true
```

- **Owner** (`Ownable2Step`, two-step transfer): `setAuthorizer`, `revoke`.
- **ERC-1271:** the authorizer can be a smart-contract wallet (Safe style); tested with a mock wallet.
- **Revocation:** `revoke` clears the flag; old signatures stay dead because their nonce was consumed.

## Run it

```bash
git clone --recurse-submodules <repo-url>
cd eip712-signature-security
forge build
forge test                                   # 56 tests: unit, exploits, fuzz, invariants
FOUNDRY_PROFILE=ci forge test                # 5000 fuzz runs, 512x256 invariants
forge coverage --no-match-coverage "script|test" --report summary   # 100 % lines in src/
```

### End-to-end on a local node (viem)

```bash
anvil                                        # terminal 1
forge script script/LocalDeploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast   # terminal 2, prints the address
cd client && npm install
AUTHORIZER_CONTRACT=0x<address> npm run demo
```

Expected output: the authorizer signs off-chain, the relayer submits it, `authorizedUsers[user] = true`; replaying the same signature and using a valid signature from an untrusted key both revert with `InvalidSignature`. The script ([`client/src/demo.ts`](client/src/demo.ts)) uses `signTypedData` from viem; the domain and types must match the contract exactly or the signature recovers to a different address.

## Tests

| File | Content |
|---|---|
| `test/VulnerableAttacks.t.sol` | One exploit per bug (plus fuzz for bugs 1, 2 and 3) |
| `test/SignatureAuthorizer.t.sol` | Unit tests, events, every custom error, the five attacks rejected, ERC-1271 |
| `test/SignatureAuthorizerFuzz.t.sol` | No other key authorizes, malleable twin always rejected, junk bytes rejected, deadline boundary, digest binds every field |
| `test/SignatureAuthorizerInvariant.t.sol` | Sum of nonces == successful authorizations; replays and foreign-key signatures never succeed; authorized implies a consumed nonce |

## Layout

```text
src/secure/SignatureAuthorizer.sol      the fixed design
src/vulnerable/                         four intentionally broken contracts
test/                                   exploits, unit, fuzz, invariants, ERC-1271 mock
script/Deploy.s.sol                     deployment from environment variables
script/LocalDeploy.s.sol                Anvil deployment
client/                                 viem + TypeScript demo
```

## Origin

Started from a course workshop on `ecrecover` validation. The course's "secure" version only rejected `address(0)` and still let anyone authorize themselves with their own key; that gap is bug 2 here. The rest (four vulnerable contracts, EIP-712 contract, ERC-1271, tests and viem client) is new.
