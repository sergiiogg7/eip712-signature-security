// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnEcrecoverZero
/// @notice INTENTIONALLY VULNERABLE. Educational only, never deploy.
/// @dev Flaw: `ecrecover` returns `address(0)` for an invalid signature instead of reverting. The contract compares
///      the result with `trustedSigner` and never checks it is non-zero. If `trustedSigner` is `address(0)`
///      (unset or misconfigured), any garbage signature (`v = 0, r = 0, s = 0`) is accepted.
contract VulnEcrecoverZero {
    /// @notice Address whose signature is supposed to authorize users. Nothing prevents it from being zero.
    address public immutable trustedSigner;

    /// @notice Users that obtained an authorization.
    mapping(address user => bool authorized) public authorizedUsers;

    /// @notice Emitted when a user is authorized.
    event UserAuthorized(address indexed user);

    /// @param signer Trusted signer. No validation, which is part of the flaw.
    // slither-disable-next-line missing-zero-check
    constructor(address signer) {
        trustedSigner = signer;
    }

    /// @notice Authorizes `user` if `hash` was signed by `trustedSigner`.
    function authorize(address user, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        // FLAW: the result may be address(0) and trustedSigner may be address(0) too.
        require(ecrecover(hash, v, r, s) == trustedSigner, "bad signature");
        authorizedUsers[user] = true;
        emit UserAuthorized(user);
    }
}
