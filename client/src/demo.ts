// End-to-end demo against a local Anvil node:
//   1. the authorizer signs an EIP-712 `Authorization` OFF-CHAIN (no gas, no transaction);
//   2. a relayer submits it ON-CHAIN, paying the gas;
//   3. the same signature is replayed and an attacker signs with their own key: both must fail.
//
// Usage (see README): AUTHORIZER_CONTRACT=0x... npm run demo

import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Address,
  type Hex,
} from "viem";
import { mnemonicToAccount } from "viem/accounts";
import { foundry } from "viem/chains";

const RPC_URL = process.env.RPC_URL ?? "http://127.0.0.1:8545";
const CONTRACT = process.env.AUTHORIZER_CONTRACT as Address | undefined;
if (!CONTRACT) throw new Error("Set AUTHORIZER_CONTRACT to the deployed SignatureAuthorizer address");

// Anvil's default mnemonic. Public development accounts: never use them outside a local node.
const MNEMONIC = "test test test test test test test test test test test junk";
const account = (addressIndex: number) => mnemonicToAccount(MNEMONIC, { addressIndex });

const authorizer = account(1); // the key the contract trusts (LocalDeploy.s.sol)
const relayer = account(2); // pays the gas; has no authority of its own
const user = account(3); // the user being authorized
const attacker = account(4); // signs with a valid but untrusted key

const abi = parseAbi([
  "function authorize(address user, uint256 deadline, bytes signature)",
  "function authorizedUsers(address user) view returns (bool)",
  "function authorizer() view returns (address)",
  "function nonces(address user) view returns (uint256)",
  "error InvalidSignature()",
  "error SignatureExpired(uint256 deadline)",
]);

// Must match the contract: EIP712("SignatureAuthorizer", "1") and AUTHORIZATION_TYPEHASH.
const types = {
  Authorization: [
    { name: "user", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

const publicClient = createPublicClient({ chain: foundry, transport: http(RPC_URL) });
const relayerClient = createWalletClient({ account: relayer, chain: foundry, transport: http(RPC_URL) });

async function sign(signer: ReturnType<typeof account>, nonce: bigint, deadline: bigint): Promise<Hex> {
  const chainId = await publicClient.getChainId();
  return signer.signTypedData({
    domain: { name: "SignatureAuthorizer", version: "1", chainId, verifyingContract: CONTRACT! },
    types,
    primaryType: "Authorization",
    message: { user: user.address, nonce, deadline },
  });
}

/** Simulates `authorize` and returns the revert name, or "OK" if it would succeed. */
async function trySimulate(deadline: bigint, signature: Hex): Promise<string> {
  try {
    await publicClient.simulateContract({
      address: CONTRACT!,
      abi,
      functionName: "authorize",
      args: [user.address, deadline, signature],
      account: relayer,
    });
    return "OK";
  } catch (e) {
    const name = (e as { cause?: { data?: { errorName?: string } } }).cause?.data?.errorName;
    return `reverts with ${name ?? "unknown error"}`;
  }
}

async function main() {
  const onChainAuthorizer = await publicClient.readContract({ address: CONTRACT!, abi, functionName: "authorizer" });
  if (onChainAuthorizer.toLowerCase() !== authorizer.address.toLowerCase()) {
    throw new Error(`Contract trusts ${onChainAuthorizer}, but this demo signs with ${authorizer.address}`);
  }

  const nonce = await publicClient.readContract({ address: CONTRACT!, abi, functionName: "nonces", args: [user.address] });
  const block = await publicClient.getBlock();
  const deadline = block.timestamp + 3600n;

  console.log(`user ${user.address} | nonce ${nonce} | deadline ${deadline}`);

  // 1. Off-chain signature by the trusted authorizer.
  const signature = await sign(authorizer, nonce, deadline);
  console.log(`1. authorizer signed off-chain: ${signature.slice(0, 22)}...`);

  // 2. A relayer submits it on-chain.
  const hash = await relayerClient.writeContract({
    address: CONTRACT!,
    abi,
    functionName: "authorize",
    args: [user.address, deadline, signature],
  });
  await publicClient.waitForTransactionReceipt({ hash });
  const ok = await publicClient.readContract({ address: CONTRACT!, abi, functionName: "authorizedUsers", args: [user.address] });
  console.log(`2. relayer submitted it -> authorizedUsers[user] = ${ok}`);

  // 3a. Replay of the same signature: the nonce was consumed.
  console.log(`3a. replay of the same signature: ${await trySimulate(deadline, signature)}`);

  // 3b. Attacker signs the correct message with their own key.
  const nextNonce = await publicClient.readContract({ address: CONTRACT!, abi, functionName: "nonces", args: [user.address] });
  const forged = await sign(attacker, nextNonce, deadline);
  console.log(`3b. valid signature from an untrusted key: ${await trySimulate(deadline, forged)}`);

  if (!ok) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
