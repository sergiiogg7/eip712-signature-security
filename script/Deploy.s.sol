// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {SignatureAuthorizer} from "../src/secure/SignatureAuthorizer.sol";

/// @notice Deploys `SignatureAuthorizer` with the configuration read from the environment.
/// @dev Required variables: `PRIVATE_KEY` (deployer), `OWNER` and `AUTHORIZER`. See `.env.example`.
///      Run: forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    function run() external returns (SignatureAuthorizer deployed) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.envAddress("OWNER");
        address authorizer = vm.envAddress("AUTHORIZER");

        vm.startBroadcast(deployerKey);
        deployed = new SignatureAuthorizer(owner, authorizer);
        vm.stopBroadcast();

        console.log("SignatureAuthorizer:", address(deployed));
        console.log("owner:", owner);
        console.log("authorizer:", authorizer);
    }
}
