// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title SignatureAuthorizer
/// @notice Authorizes users with an off-chain signature from a trusted `authorizer`, done right.
/// @dev Fixes, one by one, the flaws shown in `src/vulnerable/`:
///      - EIP-712 typed data with a domain separator (name, version, chainId, verifyingContract): a signature is
///        only valid for this contract on this chain. Fixes `VulnReplay` (cross-domain).
///      - Per-user nonce inside the signed message: each signature works once and a replay fails. Fixes `VulnReplay`.
///      - Deadline inside the signed message.
///      - The signer is compared with `authorizer`. Fixes `VulnNoSignerCheck`.
///      - `SignatureChecker` uses OpenZeppelin `ECDSA` (rejects `address(0)`, bad `v` and high `s`) and falls back to
///        ERC-1271 when `authorizer` is a contract (Safe, smart wallets). Fixes `VulnEcrecoverZero` and
///        `VulnMalleableReplay`: replay protection does not depend on the signature bytes.
///      No reentrancy guard is needed: there is no ETH or token transfer and the only external call is the
///      `staticcall` of ERC-1271.
contract SignatureAuthorizer is Ownable2Step, EIP712 {
    /// @notice EIP-712 type hash of the signed message.
    bytes32 public constant AUTHORIZATION_TYPEHASH =
        keccak256("Authorization(address user,uint256 nonce,uint256 deadline)");

    /// @notice Account (EOA or ERC-1271 contract) whose signature authorizes users.
    address public authorizer;

    /// @notice Next valid nonce for each user.
    mapping(address user => uint256 nonce) public nonces;

    /// @notice Users that currently hold an authorization.
    mapping(address user => bool authorized) public authorizedUsers;

    /// @notice Emitted when `user` gets authorized.
    event UserAuthorized(address indexed user, uint256 nonce);
    /// @notice Emitted when the authorization of `user` is revoked.
    event UserRevoked(address indexed user);
    /// @notice Emitted when the authorizer changes.
    event AuthorizerChanged(address indexed previousAuthorizer, address indexed newAuthorizer);

    /// @notice A zero address was supplied.
    error ZeroAddress();
    /// @notice The signature deadline already passed.
    error SignatureExpired(uint256 deadline);
    /// @notice The signature is not valid for the current authorizer, nonce and domain.
    error InvalidSignature();
    /// @notice The user is not authorized.
    error NotAuthorized(address user);

    /// @param initialOwner Contract owner (can change the authorizer and revoke users).
    /// @param initialAuthorizer Account whose signatures authorize users.
    constructor(address initialOwner, address initialAuthorizer)
        Ownable(initialOwner)
        EIP712("SignatureAuthorizer", "1")
    {
        if (initialAuthorizer == address(0)) revert ZeroAddress();
        authorizer = initialAuthorizer;
        emit AuthorizerChanged(address(0), initialAuthorizer);
    }

    /// @notice Authorizes `user` with a signature of `authorizer` over `(user, nonces[user], deadline)`.
    /// @dev Anyone can submit the signature (relayer pattern); the signature, not `msg.sender`, is the authority.
    /// @param user User to authorize.
    /// @param deadline Last timestamp (inclusive) at which the signature is valid.
    /// @param signature 65-byte ECDSA signature, or any bytes accepted by an ERC-1271 authorizer.
    function authorize(address user, uint256 deadline, bytes calldata signature) external {
        if (user == address(0)) revert ZeroAddress();
        // A validator can skew the timestamp by seconds, irrelevant for a deadline measured in minutes or hours.
        // slither-disable-next-line timestamp
        if (block.timestamp > deadline) revert SignatureExpired(deadline);

        uint256 nonce = nonces[user];
        bytes32 digest = hashAuthorization(user, nonce, deadline);
        if (!SignatureChecker.isValidSignatureNow(authorizer, digest, signature)) revert InvalidSignature();

        nonces[user] = nonce + 1;
        authorizedUsers[user] = true;
        emit UserAuthorized(user, nonce);
    }

    /// @notice Revokes the authorization of `user`. Old signatures stay dead because the nonce was consumed.
    function revoke(address user) external onlyOwner {
        authorizedUsers[user] = false;
        emit UserRevoked(user);
    }

    /// @notice Replaces the authorizer. Signatures of the previous authorizer stop working immediately.
    function setAuthorizer(address newAuthorizer) external onlyOwner {
        if (newAuthorizer == address(0)) revert ZeroAddress();
        emit AuthorizerChanged(authorizer, newAuthorizer);
        authorizer = newAuthorizer;
    }

    /// @notice Example of a function gated by the authorization.
    /// @return Always true for authorized callers.
    function protectedAction() external view returns (bool) {
        if (!authorizedUsers[msg.sender]) revert NotAuthorized(msg.sender);
        return true;
    }

    /// @notice EIP-712 digest that the authorizer must sign.
    function hashAuthorization(address user, uint256 nonce, uint256 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(AUTHORIZATION_TYPEHASH, user, nonce, deadline)));
    }

    /// @notice EIP-712 domain separator of this deployment.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
