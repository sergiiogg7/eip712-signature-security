// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnReplay
/// @notice INTENTIONALLY VULNERABLE. Educational only, never deploy.
/// @dev Flaws: (1) no nonce or used-signature tracking, so the same signature can be submitted forever;
///      (2) the signed message has no domain (no `chainId`, no contract address), so a signature for one deployment
///      or chain is valid on every other one that trusts the same signer.
contract VulnReplay {
    /// @notice Address whose signature authorizes a claim.
    address public immutable trustedSigner;

    /// @notice Credits obtained by each user.
    mapping(address user => uint256 amount) public credits;

    /// @notice Emitted when credits are granted.
    event Claimed(address indexed user, uint256 amount);

    /// @param signer Trusted signer.
    constructor(address signer) {
        require(signer != address(0), "zero signer");
        trustedSigner = signer;
    }

    /// @notice Grants `amount` credits to `user` if `trustedSigner` signed `(user, amount)`.
    function claim(address user, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        // FLAW: the hash is not bound to this contract, this chain, a nonce or a deadline.
        bytes32 hash = keccak256(abi.encodePacked(user, amount));
        require(ecrecover(hash, v, r, s) == trustedSigner, "bad signature");
        credits[user] += amount;
        emit Claimed(user, amount);
    }
}
