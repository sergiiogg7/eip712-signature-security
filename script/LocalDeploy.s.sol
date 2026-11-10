// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {SignatureAuthorizer} from "../src/secure/SignatureAuthorizer.sol";

/// @notice Local deployment on Anvil using its well-known development accounts.
/// @dev Anvil account #0 deploys and owns the contract, account #1 is the authorizer (the key that signs).
///      These keys are public and only valid on a local node: never use them on a real network.
///      Run: forge script script/LocalDeploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
contract LocalDeploy is Script {
    /// @dev Anvil account #0 private key (public development key).
    uint256 internal constant ANVIL_DEPLOYER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    /// @dev Anvil account #1 address.
    address internal constant ANVIL_AUTHORIZER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    function run() external returns (SignatureAuthorizer deployed) {
        address owner = vm.addr(ANVIL_DEPLOYER_KEY);

        vm.startBroadcast(ANVIL_DEPLOYER_KEY);
        deployed = new SignatureAuthorizer(owner, ANVIL_AUTHORIZER);
        vm.stopBroadcast();

        console.log("SignatureAuthorizer:", address(deployed));
    }
}
