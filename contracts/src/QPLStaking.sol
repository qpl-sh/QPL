// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IQPLStaking} from "./interfaces/IQPLStaking.sol";

/// @title QPLStaking
/// @notice Manages operator stake, registration, and slashing for the QPL network.
/// @dev Operators stake ETH to participate. Minimum stake enforced.
///      Unbonding period prevents immediate withdrawal (7 days default).
contract QPLStaking is IQPLStaking {
    // ─── State ─────────────────────────────────────────────────────────

    struct Operator {
        address staker;
        uint256 stakedAmount;
        string endpoint;
        uint32 servicesBitmask;
        bool active;
        uint256 unstakeTime; // 0 = not unstaking
    }

    /// @notice Minimum stake required (1 ETH).
    uint256 public constant MIN_STAKE = 1 ether;

    /// @notice Unbonding period (7 days).
    uint256 public constant UNBOND_PERIOD = 7 days;

    /// @notice Governance address (can slash).
    address public governance;

    /// @notice Operator ID => Operator data.
    mapping(bytes32 => Operator) public operators;

    /// @notice Active operator IDs.
    bytes32[] private _activeOperators;

    /// @notice Index of operator in _activeOperators array.
    mapping(bytes32 => uint256) private _activeIndex;

    // ─── Modifiers ─────────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governance, "QPLStaking: not governance");
        _;
    }

    modifier onlyOperatorOwner(bytes32 operatorId) {
        require(operators[operatorId].staker == msg.sender, "QPLStaking: not owner");
        _;
    }

    // ─── Constructor ───────────────────────────────────────────────────

    constructor(address _governance) {
        governance = _governance;
    }

    // ─── External Functions ────────────────────────────────────────────

    /// @inheritdoc IQPLStaking
    function stake(
        bytes32 operatorId,
        string calldata endpoint,
        uint32 servicesBitmask
    ) external payable {
        require(msg.value >= MIN_STAKE, "QPLStaking: insufficient stake");
        require(operators[operatorId].staker == address(0), "QPLStaking: already registered");
        require(servicesBitmask > 0, "QPLStaking: must support at least one service");

        operators[operatorId] = Operator({
            staker: msg.sender,
            stakedAmount: msg.value,
            endpoint: endpoint,
            servicesBitmask: servicesBitmask,
            active: true,
            unstakeTime: 0
        });

        _activeIndex[operatorId] = _activeOperators.length;
        _activeOperators.push(operatorId);

        emit OperatorStaked(operatorId, msg.sender, msg.value);
    }

    /// @inheritdoc IQPLStaking
    function initiateUnstake(bytes32 operatorId) external onlyOperatorOwner(operatorId) {
        Operator storage op = operators[operatorId];
        require(op.active, "QPLStaking: not active");
        require(op.unstakeTime == 0, "QPLStaking: already unstaking");

        op.active = false;
        op.unstakeTime = block.timestamp + UNBOND_PERIOD;

        _removeFromActive(operatorId);

        emit UnstakeInitiated(operatorId, op.unstakeTime);
    }

    /// @inheritdoc IQPLStaking
    function withdraw(bytes32 operatorId) external onlyOperatorOwner(operatorId) {
        Operator storage op = operators[operatorId];
        require(op.unstakeTime > 0, "QPLStaking: not unstaking");
        require(block.timestamp >= op.unstakeTime, "QPLStaking: unbonding period not elapsed");

        uint256 amount = op.stakedAmount;
        op.stakedAmount = 0;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "QPLStaking: transfer failed");

        emit StakeWithdrawn(operatorId, amount);
    }

    /// @inheritdoc IQPLStaking
    function slash(
        bytes32 operatorId,
        uint256 amount,
        bytes calldata reason
    ) external onlyGovernance {
        Operator storage op = operators[operatorId];
        require(op.stakedAmount >= amount, "QPLStaking: slash exceeds stake");

        op.stakedAmount -= amount;

        // If stake falls below minimum, deactivate
        if (op.stakedAmount < MIN_STAKE && op.active) {
            op.active = false;
            _removeFromActive(operatorId);
        }

        // Send slashed amount to governance (treasury)
        (bool success, ) = payable(governance).call{value: amount}("");
        require(success, "QPLStaking: transfer failed");

        emit OperatorSlashed(operatorId, amount, reason);
    }

    /// @inheritdoc IQPLStaking
    function getOperator(bytes32 operatorId) external view returns (
        address staker,
        uint256 stakedAmount,
        string memory endpoint,
        uint32 servicesBitmask,
        bool active,
        uint256 unstakeTime
    ) {
        Operator storage op = operators[operatorId];
        return (op.staker, op.stakedAmount, op.endpoint, op.servicesBitmask, op.active, op.unstakeTime);
    }

    /// @inheritdoc IQPLStaking
    function getActiveOperators() external view returns (bytes32[] memory) {
        return _activeOperators;
    }

    /// @inheritdoc IQPLStaking
    function minStake() external pure returns (uint256) {
        return MIN_STAKE;
    }

    // ─── Internal ──────────────────────────────────────────────────────

    function _removeFromActive(bytes32 operatorId) internal {
        uint256 idx = _activeIndex[operatorId];
        uint256 lastIdx = _activeOperators.length - 1;

        if (idx != lastIdx) {
            bytes32 lastId = _activeOperators[lastIdx];
            _activeOperators[idx] = lastId;
            _activeIndex[lastId] = idx;
        }

        _activeOperators.pop();
        delete _activeIndex[operatorId];
    }
}
