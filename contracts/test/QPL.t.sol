// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {QPLStaking} from "../src/QPLStaking.sol";
import {QPLFeeRouter} from "../src/QPLFeeRouter.sol";
import {QPLRegistry} from "../src/QPLRegistry.sol";

contract QPLStakingTest is Test {
    QPLStaking public staking;
    address public governance = address(0x900);
    address public operator1 = address(0x1);
    bytes32 public opId1 = keccak256("operator-1-pubkey");

    function setUp() public {
        staking = new QPLStaking(governance);
        vm.deal(operator1, 10 ether);
    }

    function test_stake() public {
        vm.prank(operator1);
        staking.stake{value: 1 ether}(opId1, "http://localhost:9000", 0x1F);

        (address staker, uint256 amount, , uint32 services, bool active, ) = staking.getOperator(opId1);
        assertEq(staker, operator1);
        assertEq(amount, 1 ether);
        assertEq(services, 0x1F); // all 5 services
        assertTrue(active);
    }

    function test_stake_insufficient() public {
        vm.prank(operator1);
        vm.expectRevert("QPLStaking: insufficient stake");
        staking.stake{value: 0.5 ether}(opId1, "http://localhost:9000", 0x01);
    }

    function test_stake_duplicate() public {
        vm.prank(operator1);
        staking.stake{value: 1 ether}(opId1, "http://localhost:9000", 0x01);

        vm.prank(operator1);
        vm.expectRevert("QPLStaking: already registered");
        staking.stake{value: 1 ether}(opId1, "http://localhost:9010", 0x01);
    }

    function test_unstake_and_withdraw() public {
        vm.prank(operator1);
        staking.stake{value: 2 ether}(opId1, "http://localhost:9000", 0x01);

        // Initiate unstake
        vm.prank(operator1);
        staking.initiateUnstake(opId1);

        (, , , , bool active, uint256 unstakeTime) = staking.getOperator(opId1);
        assertFalse(active);
        assertGt(unstakeTime, 0);

        // Cannot withdraw before unbonding
        vm.prank(operator1);
        vm.expectRevert("QPLStaking: unbonding period not elapsed");
        staking.withdraw(opId1);

        // Warp past unbonding period
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balBefore = operator1.balance;
        vm.prank(operator1);
        staking.withdraw(opId1);
        assertEq(operator1.balance - balBefore, 2 ether);
    }

    function test_slash() public {
        vm.prank(operator1);
        staking.stake{value: 2 ether}(opId1, "http://localhost:9000", 0x01);

        vm.prank(governance);
        staking.slash(opId1, 0.5 ether, "missed heartbeats");

        (, uint256 amount, , , bool active, ) = staking.getOperator(opId1);
        assertEq(amount, 1.5 ether);
        assertTrue(active); // still above min stake

        // Slash below min => deactivated
        vm.prank(governance);
        staking.slash(opId1, 1 ether, "critical failure");

        (, uint256 amount2, , , bool active2, ) = staking.getOperator(opId1);
        assertEq(amount2, 0.5 ether);
        assertFalse(active2);
    }

    function test_active_operators() public {
        vm.prank(operator1);
        staking.stake{value: 1 ether}(opId1, "http://localhost:9000", 0x01);

        bytes32[] memory ops = staking.getActiveOperators();
        assertEq(ops.length, 1);
        assertEq(ops[0], opId1);

        vm.prank(operator1);
        staking.initiateUnstake(opId1);

        bytes32[] memory ops2 = staking.getActiveOperators();
        assertEq(ops2.length, 0);
    }
}

contract QPLFeeRouterTest is Test {
    QPLFeeRouter public router;
    address public treasury = address(0x7EA5);
    address public governance = address(0x900);
    address public protocol = address(0xABC);
    address public coordinator = address(0xC00);
    address public participant1 = address(0xA1);
    address public participant2 = address(0xA2);
    bytes32 public quoteId = keccak256("quote-1");
    bytes32 public opId = keccak256("operator-1");

    function setUp() public {
        router = new QPLFeeRouter(treasury, governance);
        vm.deal(protocol, 10 ether);
    }

    function test_pay_fee() public {
        vm.prank(protocol);
        router.payFee{value: 0.001 ether}(quoteId, opId);

        assertTrue(router.isPaid(quoteId));
        assertEq(router.quoteFees(quoteId), 0.001 ether);
    }

    function test_pay_fee_duplicate() public {
        vm.prank(protocol);
        router.payFee{value: 0.001 ether}(quoteId, opId);

        vm.prank(protocol);
        vm.expectRevert("QPLFeeRouter: already paid");
        router.payFee{value: 0.001 ether}(quoteId, opId);
    }

    function test_distribute_and_claim() public {
        // Pay fee
        vm.prank(protocol);
        router.payFee{value: 1 ether}(quoteId, opId);

        // Distribute
        address[] memory participants = new address[](2);
        participants[0] = participant1;
        participants[1] = participant2;

        vm.prank(governance);
        router.distributeFee(quoteId, coordinator, participants);

        // Verify splits: 40% coord, 50% participants (25% each), 10% treasury
        assertEq(router.claimable(coordinator), 0.4 ether);
        assertEq(router.claimable(participant1), 0.25 ether);
        assertEq(router.claimable(participant2), 0.25 ether);

        // Claim coordinator
        vm.prank(coordinator);
        router.claim();
        assertEq(coordinator.balance, 0.4 ether);
        assertEq(router.claimable(coordinator), 0);
    }

    function test_fee_split_constants() public view {
        (uint8 c, uint8 p, uint8 t) = router.getFeeSplit();
        assertEq(c, 40);
        assertEq(p, 50);
        assertEq(t, 10);
        assertEq(uint8(c) + uint8(p) + uint8(t), 100);
    }
}
