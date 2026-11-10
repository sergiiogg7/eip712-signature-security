// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SignatureAuthorizer} from "../src/secure/SignatureAuthorizer.sol";

contract SignatureAuthorizerFuzzTest is Test {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant AUTHORIZER_KEY = 0xA11CE;

    SignatureAuthorizer internal auth;
    address internal owner = makeAddr("owner");

    function setUp() public {
        auth = new SignatureAuthorizer(owner, vm.addr(AUTHORIZER_KEY));
    }

    /// @dev Any valid signature of the authorizer, for any user and any future deadline, authorizes exactly once.
    function testFuzz_ValidSignatureAuthorizesOnce(address user, uint64 extra) public {
        vm.assume(user != address(0));
        uint256 deadline = block.timestamp + extra;
        bytes memory sig = _sign(AUTHORIZER_KEY, user, 0, deadline);

        auth.authorize(user, deadline, sig);
        assertTrue(auth.authorizedUsers(user));
        assertEq(auth.nonces(user), 1);

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(user, deadline, sig);
    }

    /// @dev No key other than the authorizer's can authorize anyone.
    function testFuzz_OtherKeysNeverAuthorize(uint256 key, address user) public {
        key = bound(key, 1, SECP256K1_N - 1);
        vm.assume(key != AUTHORIZER_KEY);
        vm.assume(user != address(0));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _sign(key, user, 0, deadline);

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(user, deadline, sig);
        assertFalse(auth.authorizedUsers(user));
    }

    /// @dev The malleable twin of any valid signature is always rejected.
    function testFuzz_MalleableTwinAlwaysRejected(address user, uint64 extra) public {
        vm.assume(user != address(0));
        uint256 deadline = block.timestamp + extra;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUTHORIZER_KEY, auth.hashAuthorization(user, 0, deadline));
        bytes memory twin = abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(user, deadline, twin);
    }

    /// @dev Arbitrary bytes are never accepted as a signature.
    function testFuzz_RandomBytesNeverAuthorize(address user, bytes calldata junk) public {
        vm.assume(user != address(0));
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(user, block.timestamp + 1 days, junk);
    }

    /// @dev A signature is valid up to the deadline (inclusive) and dead after it.
    function testFuzz_DeadlineBoundary(uint32 delta, uint32 ttl) public {
        address user = makeAddr("user");
        uint256 deadline = block.timestamp + ttl;
        bytes memory sig = _sign(AUTHORIZER_KEY, user, 0, deadline);
        vm.warp(block.timestamp + delta);

        if (block.timestamp > deadline) {
            vm.expectRevert(abi.encodeWithSelector(SignatureAuthorizer.SignatureExpired.selector, deadline));
        }
        auth.authorize(user, deadline, sig);
    }

    /// @dev The digest depends on every field: changing any one gives a different digest.
    function testFuzz_DigestBindsAllFields(address user, uint256 nonce, uint256 deadline) public view {
        bytes32 base = auth.hashAuthorization(user, nonce, deadline);
        assertTrue(base != auth.hashAuthorization(address(uint160(user) ^ 1), nonce, deadline));
        assertTrue(base != auth.hashAuthorization(user, nonce ^ 1, deadline));
        assertTrue(base != auth.hashAuthorization(user, nonce, deadline ^ 1));
    }

    function _sign(uint256 key, address user, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, auth.hashAuthorization(user, nonce, deadline));
        return abi.encodePacked(r, s, v);
    }
}
