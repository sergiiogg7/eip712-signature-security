// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnMalleableReplay
/// @notice INTENTIONALLY VULNERABLE. Educational only, never deploy.
/// @dev Flaw: replay protection is keyed by the signature bytes. For every valid ECDSA signature `(v, r, s)` there
///      is a second valid one `(v', r, n - s)` for the same signer and message (signature malleability). An attacker
///      flips `s` and `v`, gets a different "signature id" and claims again.
contract VulnMalleableReplay {
    /// @notice Address whose signature authorizes a claim.
    address public immutable trustedSigner;

    /// @notice Credits obtained by each user.
    mapping(address user => uint256 amount) public credits;

    /// @notice Signature ids already consumed.
    mapping(bytes32 sigId => bool used) public usedSignatures;

    /// @notice Emitted when credits are granted.
    event Claimed(address indexed user, uint256 amount);

    /// @param signer Trusted signer.
    constructor(address signer) {
        require(signer != address(0), "zero signer");
        trustedSigner = signer;
    }

    /// @notice Grants `amount` credits to `user` if `trustedSigner` signed `(user, amount)`.
    function claim(address user, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 sigId = keccak256(abi.encodePacked(v, r, s)); // FLAW: malleable identifier
        require(!usedSignatures[sigId], "already used");

        bytes32 hash = keccak256(abi.encodePacked(user, amount));
        require(ecrecover(hash, v, r, s) == trustedSigner, "bad signature");

        usedSignatures[sigId] = true;
        credits[user] += amount;
        emit Claimed(user, amount);
    }
}
