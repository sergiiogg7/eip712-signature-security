// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnNoSignerCheck
/// @notice INTENTIONALLY VULNERABLE. Educational only, never deploy.
/// @dev Flaw: the contract verifies that the signature is valid but never checks WHO signed it. This is the flaw
///      that the original course "secure" version still had: anyone signs with their own key and authorizes
///      themselves. A valid signature only proves that someone signed, not that the right person did.
contract VulnNoSignerCheck {
    /// @notice Users that obtained an authorization.
    mapping(address user => bool authorized) public authorizedUsers;

    /// @notice Emitted when a user is authorized.
    event UserAuthorized(address indexed user, address indexed signer);

    /// @notice Authorizes `user` if the signature is valid (for ANY signer).
    function authorize(address user, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "bad signature");
        // FLAW: `signer` is never compared with an authorized address.
        authorizedUsers[user] = true;
        emit UserAuthorized(user, signer);
    }
}
