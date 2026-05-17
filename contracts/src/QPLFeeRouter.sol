// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IQPLFeeRouter} from "./interfaces/IQPLFeeRouter.sol";

/// @title QPLFeeRouter
/// @notice Collects per-operation fees and distributes them to operators and treasury.
/// @dev Fee split: 40% coordinator, 50% participants (split equally), 10% treasury.
///      Protocols pay fees before requesting QPL services. Operators claim after completion.
contract QPLFeeRouter is IQPLFeeRouter {
    // ─── Constants ─────────────────────────────────────────────────────

    uint8 public constant COORDINATOR_PCT = 40;
    uint8 public constant PARTICIPANT_PCT = 50;
    uint8 public constant TREASURY_PCT = 10;

    // ─── State ─────────────────────────────────────────────────────────

    /// @notice Protocol treasury address.
    address public treasury;

    /// @notice Governance address (can update treasury).
    address public governance;

    /// @notice Quote ID => amount paid.
    mapping(bytes32 => uint256) public quoteFees;

    /// @notice Quote ID => whether it has been distributed.
    mapping(bytes32 => bool) public distributed;

    /// @notice Quote ID => payer address.
    mapping(bytes32 => address) public quotePayer;

    /// @notice Operator address => claimable balance.
    mapping(address => uint256) public claimable;

    // ─── Events ────────────────────────────────────────────────────────

    event TreasuryUpdated(address indexed newTreasury);
    event FeesClaimed(address indexed operator, uint256 amount);

    // ─── Modifiers ─────────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governance, "QPLFeeRouter: not governance");
        _;
    }

    // ─── Constructor ───────────────────────────────────────────────────

    constructor(address _treasury, address _governance) {
        treasury = _treasury;
        governance = _governance;
    }

    // ─── External Functions ────────────────────────────────────────────

    /// @inheritdoc IQPLFeeRouter
    function payFee(bytes32 quoteId, bytes32 operatorId) external payable {
        require(msg.value > 0, "QPLFeeRouter: zero fee");
        require(quoteFees[quoteId] == 0, "QPLFeeRouter: already paid");

        quoteFees[quoteId] = msg.value;
        quotePayer[quoteId] = msg.sender;

        emit FeePaid(quoteId, operatorId, msg.sender, msg.value);
    }

    /// @inheritdoc IQPLFeeRouter
    function distributeFee(
        bytes32 quoteId,
        address coordinator,
        address[] calldata participants
    ) external onlyGovernance {
        require(quoteFees[quoteId] > 0, "QPLFeeRouter: not paid");
        require(!distributed[quoteId], "QPLFeeRouter: already distributed");

        distributed[quoteId] = true;
        uint256 totalFee = quoteFees[quoteId];

        // Calculate splits
        uint256 coordinatorAmount = (totalFee * COORDINATOR_PCT) / 100;
        uint256 treasuryAmount = (totalFee * TREASURY_PCT) / 100;
        uint256 participantPool = totalFee - coordinatorAmount - treasuryAmount;

        // Credit coordinator
        claimable[coordinator] += coordinatorAmount;

        // Credit participants equally
        if (participants.length > 0) {
            uint256 perParticipant = participantPool / participants.length;
            for (uint256 i = 0; i < participants.length; i++) {
                claimable[participants[i]] += perParticipant;
            }
            // Dust goes to coordinator
            uint256 dust = participantPool - (perParticipant * participants.length);
            if (dust > 0) {
                claimable[coordinator] += dust;
            }
        } else {
            // No participants — coordinator gets participant share too
            claimable[coordinator] += participantPool;
        }

        // Send treasury share immediately
        (bool success, ) = payable(treasury).call{value: treasuryAmount}("");
        require(success, "QPLFeeRouter: treasury transfer failed");

        emit FeeDistributed(quoteId, coordinatorAmount, participantPool, treasuryAmount);
    }

    /// @notice Claim accumulated fees.
    function claim() external {
        uint256 amount = claimable[msg.sender];
        require(amount > 0, "QPLFeeRouter: nothing to claim");

        claimable[msg.sender] = 0;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "QPLFeeRouter: claim transfer failed");

        emit FeesClaimed(msg.sender, amount);
    }

    /// @inheritdoc IQPLFeeRouter
    function getFeeSplit() external pure returns (uint8, uint8, uint8) {
        return (COORDINATOR_PCT, PARTICIPANT_PCT, TREASURY_PCT);
    }

    /// @inheritdoc IQPLFeeRouter
    function isPaid(bytes32 quoteId) external view returns (bool) {
        return quoteFees[quoteId] > 0;
    }

    /// @notice Update treasury address (governance only).
    function setTreasury(address _treasury) external onlyGovernance {
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }
}
