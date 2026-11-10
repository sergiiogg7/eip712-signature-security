// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {SignatureAuthorizer} from "../src/secure/SignatureAuthorizer.sol";
import {MockERC1271Wallet} from "./mocks/MockERC1271Wallet.sol";

/// @notice Unit tests of the secure contract. The "attack" tests replay, against `SignatureAuthorizer`, the exploits
///         that succeed in `VulnerableAttacks.t.sol`; here all of them must fail.
contract SignatureAuthorizerTest is Test {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant AUTHORIZER_KEY = 0xA11CE;
    uint256 internal constant ATTACKER_KEY = 0xBAD;

    SignatureAuthorizer internal auth;
    address internal authorizer;
    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal attacker;
    uint256 internal deadline;

    function setUp() public {
        authorizer = vm.addr(AUTHORIZER_KEY);
        attacker = vm.addr(ATTACKER_KEY);
        auth = new SignatureAuthorizer(owner, authorizer);
        deadline = block.timestamp + 1 hours;
    }

    // --- constructor / happy path ---

    function test_ConstructorSetsState() public view {
        assertEq(auth.owner(), owner);
        assertEq(auth.authorizer(), authorizer);
        assertEq(auth.AUTHORIZATION_TYPEHASH(), keccak256("Authorization(address user,uint256 nonce,uint256 deadline)"));
    }

    function test_RevertWhen_ConstructorAuthorizerIsZero() public {
        vm.expectRevert(SignatureAuthorizer.ZeroAddress.selector);
        new SignatureAuthorizer(owner, address(0));
    }

    function test_Authorize_ValidSignature() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);

        vm.expectEmit(true, false, false, true, address(auth));
        emit SignatureAuthorizer.UserAuthorized(alice, 0);
        auth.authorize(alice, deadline, sig);

        assertTrue(auth.authorizedUsers(alice));
        assertEq(auth.nonces(alice), 1);
    }

    function test_Authorize_AnyoneCanRelay() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        vm.prank(makeAddr("relayer"));
        auth.authorize(alice, deadline, sig);
        assertTrue(auth.authorizedUsers(alice));
    }

    function test_Authorize_DeadlineIsInclusive() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        vm.warp(deadline);
        auth.authorize(alice, deadline, sig);
        assertTrue(auth.authorizedUsers(alice));
    }

    function test_ProtectedAction() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SignatureAuthorizer.NotAuthorized.selector, alice));
        auth.protectedAction();

        auth.authorize(alice, deadline, _sign(AUTHORIZER_KEY, alice, 0, deadline));
        vm.prank(alice);
        assertTrue(auth.protectedAction());
    }

    function test_DomainSeparatorMatchesDigest() public view {
        bytes32 structHash = keccak256(abi.encode(auth.AUTHORIZATION_TYPEHASH(), alice, uint256(0), deadline));
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", auth.domainSeparator(), structHash));
        assertEq(auth.hashAuthorization(alice, 0, deadline), expected);
    }

    // --- input validation ---

    function test_RevertWhen_UserIsZero() public {
        vm.expectRevert(SignatureAuthorizer.ZeroAddress.selector);
        auth.authorize(address(0), deadline, "");
    }

    function test_RevertWhen_Expired() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(SignatureAuthorizer.SignatureExpired.selector, deadline));
        auth.authorize(alice, deadline, sig);
    }

    // --- attacks from VulnerableAttacks.t.sol, now rejected ---

    /// @dev Counterpart of `VulnEcrecoverZero`: garbage signature (v = 0, r = 0, s = 0).
    function test_Attack_GarbageSignatureRejected() public {
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(attacker, deadline, new bytes(65));
    }

    function test_Attack_WrongLengthSignatureRejected() public {
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(attacker, deadline, hex"1234");
    }

    function test_Attack_InvalidVRejected() public {
        (, bytes32 r, bytes32 s) = vm.sign(AUTHORIZER_KEY, auth.hashAuthorization(alice, 0, deadline));
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, abi.encodePacked(r, s, uint8(29)));
    }

    /// @dev Counterpart of `VulnNoSignerCheck`: valid signature, wrong signer.
    function test_Attack_SignatureFromAttackerKeyRejected() public {
        bytes memory sig = _sign(ATTACKER_KEY, attacker, 0, deadline);
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(attacker, deadline, sig);
        assertFalse(auth.authorizedUsers(attacker));
    }

    /// @dev Counterpart of `VulnMalleableReplay`: the malleable twin `(n - s, flipped v)` is not accepted.
    function test_Attack_MalleableTwinRejected() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUTHORIZER_KEY, auth.hashAuthorization(alice, 0, deadline));
        bytes memory twin = abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, twin);
    }

    /// @dev Even if the twin were accepted, replay protection is the nonce, not the signature bytes.
    function test_Attack_ReplayWithSameSignatureRejected() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        auth.authorize(alice, deadline, sig);

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, sig);
    }

    function test_Attack_ReplayAfterRevokeRejected() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        auth.authorize(alice, deadline, sig);

        vm.prank(owner);
        auth.revoke(alice);
        assertFalse(auth.authorizedUsers(alice));

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, sig);
        assertFalse(auth.authorizedUsers(alice));
    }

    function test_Authorize_AfterRevokeNeedsFreshSignature() public {
        auth.authorize(alice, deadline, _sign(AUTHORIZER_KEY, alice, 0, deadline));
        vm.prank(owner);
        auth.revoke(alice);

        auth.authorize(alice, deadline, _sign(AUTHORIZER_KEY, alice, 1, deadline));
        assertTrue(auth.authorizedUsers(alice));
        assertEq(auth.nonces(alice), 2);
    }

    /// @dev Counterpart of `VulnReplay` (cross-deployment).
    function test_Attack_SignatureForAnotherDeploymentRejected() public {
        SignatureAuthorizer other = new SignatureAuthorizer(owner, authorizer);
        bytes memory sigForOther = _signFor(other, AUTHORIZER_KEY, alice, 0, deadline);

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, sigForOther);

        other.authorize(alice, deadline, sigForOther);
        assertTrue(other.authorizedUsers(alice));
        assertFalse(auth.authorizedUsers(alice));
    }

    /// @dev Counterpart of `VulnReplay` (cross-chain): the domain separator includes `chainId`.
    function test_Attack_SignatureFromAnotherChainRejected() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        vm.chainId(block.chainid + 1);
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, sig);
    }

    function test_Attack_SignatureReusedForOtherUserRejected() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(attacker, deadline, sig);
    }

    function test_Attack_ExtendedDeadlineRejected() public {
        bytes memory sig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline + 1 days, sig);
    }

    // --- admin ---

    function test_SetAuthorizer_OldSignaturesStopWorking() public {
        bytes memory oldSig = _sign(AUTHORIZER_KEY, alice, 0, deadline);
        address newAuthorizer = makeAddr("new authorizer");

        vm.expectEmit(true, true, false, false, address(auth));
        emit SignatureAuthorizer.AuthorizerChanged(authorizer, newAuthorizer);
        vm.prank(owner);
        auth.setAuthorizer(newAuthorizer);

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        auth.authorize(alice, deadline, oldSig);
    }

    function test_RevertWhen_SetAuthorizerZero() public {
        vm.prank(owner);
        vm.expectRevert(SignatureAuthorizer.ZeroAddress.selector);
        auth.setAuthorizer(address(0));
    }

    function test_RevertWhen_NonOwnerAdmin() public {
        vm.startPrank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        auth.setAuthorizer(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        auth.revoke(alice);
        vm.stopPrank();
    }

    function test_Revoke_EmitsEvent() public {
        vm.expectEmit(true, false, false, false, address(auth));
        emit SignatureAuthorizer.UserRevoked(alice);
        vm.prank(owner);
        auth.revoke(alice);
    }

    function test_OwnershipIsTwoStep() public {
        address newOwner = makeAddr("new owner");
        vm.prank(owner);
        auth.transferOwnership(newOwner);
        assertEq(auth.owner(), owner);

        vm.prank(newOwner);
        auth.acceptOwnership();
        assertEq(auth.owner(), newOwner);
    }

    // --- ERC-1271 (smart contract authorizer) ---

    function test_Erc1271_WalletAuthorizerAcceptsOwnerSignature() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(authorizer);
        SignatureAuthorizer a = new SignatureAuthorizer(owner, address(wallet));

        bytes memory sig = _signFor(a, AUTHORIZER_KEY, alice, 0, deadline);
        a.authorize(alice, deadline, sig);
        assertTrue(a.authorizedUsers(alice));
    }

    function test_Erc1271_WalletAuthorizerRejectsOtherSignature() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(authorizer);
        SignatureAuthorizer a = new SignatureAuthorizer(owner, address(wallet));

        bytes memory sig = _signFor(a, ATTACKER_KEY, alice, 0, deadline);
        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        a.authorize(alice, deadline, sig);
    }

    function test_Erc1271_WalletAuthorizerRejectsGarbage() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(authorizer);
        SignatureAuthorizer a = new SignatureAuthorizer(owner, address(wallet));

        vm.expectRevert(SignatureAuthorizer.InvalidSignature.selector);
        a.authorize(alice, deadline, new bytes(65));
    }

    // --- helpers ---

    function _sign(uint256 key, address user, uint256 nonce, uint256 dl) internal view returns (bytes memory) {
        return _signFor(auth, key, user, nonce, dl);
    }

    function _signFor(SignatureAuthorizer target, uint256 key, address user, uint256 nonce, uint256 dl)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, target.hashAuthorization(user, nonce, dl));
        return abi.encodePacked(r, s, v);
    }
}
