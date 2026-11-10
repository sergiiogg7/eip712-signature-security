// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SignatureAuthorizer} from "../src/secure/SignatureAuthorizer.sol";

/// @dev Drives the contract with valid signatures, replays, signatures from foreign keys and revocations,
///      and records in ghost variables how many authorizations really succeeded.
contract InvHandler is Test {
    uint256 internal constant AUTHORIZER_KEY = 0xA11CE;
    uint256 internal constant ATTACKER_KEY = 0xBAD;

    SignatureAuthorizer public immutable auth;
    address public immutable owner;
    address[] public actors;

    uint256 public ghostSuccessfulAuthorizations;
    uint256 public ghostAttackerSuccesses;
    bytes internal lastSig;
    address internal lastUser;
    uint256 internal lastDeadline;

    constructor(SignatureAuthorizer auth_, address owner_) {
        auth = auth_;
        owner = owner_;
        for (uint256 i; i < 4; ++i) {
            actors.push(makeAddr(string.concat("actor", vm.toString(i))));
        }
    }

    function actorsLength() external view returns (uint256) {
        return actors.length;
    }

    /// @dev Fresh, valid signature for the current nonce.
    function authorizeValid(uint256 actorSeed) external {
        address user = actors[actorSeed % actors.length];
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _sign(AUTHORIZER_KEY, user, auth.nonces(user), deadline);
        auth.authorize(user, deadline, sig);
        ghostSuccessfulAuthorizations++;
        lastSig = sig;
        lastUser = user;
        lastDeadline = deadline;
    }

    /// @dev Replay of the last used signature. It must always fail.
    function replayLast() external {
        if (lastSig.length == 0) return;
        try auth.authorize(lastUser, lastDeadline, lastSig) {
            ghostAttackerSuccesses++;
        } catch {}
    }

    /// @dev Valid signature made with a key that is not the authorizer's. It must always fail.
    function authorizeWithForeignKey(uint256 actorSeed) external {
        address user = actors[actorSeed % actors.length];
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _sign(ATTACKER_KEY, user, auth.nonces(user), deadline);
        try auth.authorize(user, deadline, sig) {
            ghostAttackerSuccesses++;
        } catch {}
    }

    function revoke(uint256 actorSeed) external {
        vm.prank(owner);
        auth.revoke(actors[actorSeed % actors.length]);
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 0, 2 days));
    }

    function _sign(uint256 key, address user, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, auth.hashAuthorization(user, nonce, deadline));
        return abi.encodePacked(r, s, v);
    }
}

contract SignatureAuthorizerInvariantTest is Test {
    SignatureAuthorizer internal auth;
    InvHandler internal handler;

    function setUp() public {
        address owner = makeAddr("owner");
        auth = new SignatureAuthorizer(owner, vm.addr(0xA11CE));
        handler = new InvHandler(auth, owner);
        targetContract(address(handler));
    }

    /// @dev The sum of all nonces equals the number of successful authorizations: each signature is consumed once.
    function invariant_NoncesEqualSuccessfulAuthorizations() public view {
        uint256 sum;
        for (uint256 i; i < handler.actorsLength(); ++i) {
            sum += auth.nonces(handler.actors(i));
        }
        assertEq(sum, handler.ghostSuccessfulAuthorizations());
    }

    /// @dev Replays and signatures from foreign keys never succeed.
    function invariant_AttacksNeverSucceed() public view {
        assertEq(handler.ghostAttackerSuccesses(), 0);
    }

    /// @dev Nobody is authorized without having consumed a signature.
    function invariant_AuthorizedImpliesConsumedNonce() public view {
        for (uint256 i; i < handler.actorsLength(); ++i) {
            address a = handler.actors(i);
            if (auth.authorizedUsers(a)) assertGt(auth.nonces(a), 0);
        }
    }
}
