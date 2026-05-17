// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {QPLStaking} from "../src/QPLStaking.sol";
import {QPLFeeRouter} from "../src/QPLFeeRouter.sol";
import {QPLRegistry} from "../src/QPLRegistry.sol";

/// @notice Deploy the QPL contract suite to a local testnet.
contract DeployQPL is Script {
    function run() external {
        address deployer = msg.sender;

        vm.startBroadcast();

        // Deploy staking (governance = deployer for testnet)
        QPLStaking staking = new QPLStaking(deployer);

        // Deploy fee router (treasury = deployer for testnet)
        QPLFeeRouter feeRouter = new QPLFeeRouter(deployer, deployer);

        // Deploy registry (staking contract can register operators)
        QPLRegistry registry = new QPLRegistry(address(staking), deployer);

        vm.stopBroadcast();

        console.log("QPLStaking:   ", address(staking));
        console.log("QPLFeeRouter: ", address(feeRouter));
        console.log("QPLRegistry:  ", address(registry));
    }
}
