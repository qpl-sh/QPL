// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IQPLStaking
/// @notice Interface for the QPL operator staking contract.
interface IQPLStaking {
    /// @notice Emitted when an operator stakes and registers.
    event OperatorStaked(bytes32 indexed operatorId, address indexed staker, uint256 amount);
    
    /// @notice Emitted when an operator begins unstaking.
    event UnstakeInitiated(bytes32 indexed operatorId, uint256 unlockTime);
    
    /// @notice Emitted when stake is withdrawn after unbonding.
    event StakeWithdrawn(bytes32 indexed operatorId, uint256 amount);
    
    /// @notice Emitted when an operator is slashed.
    event OperatorSlashed(bytes32 indexed operatorId, uint256 amount, bytes reason);

    /// @notice Stake tokens and register as an operator.
    /// @param operatorId SHA-256 hash of the operator's ML-DSA public key.
    /// @param endpoint The operator's gRPC endpoint URL.
    /// @param servicesBitmask Bitmask of supported services.
    function stake(bytes32 operatorId, string calldata endpoint, uint32 servicesBitmask) external payable;

    /// @notice Initiate unstaking (begins unbonding period).
    function initiateUnstake(bytes32 operatorId) external;

    /// @notice Withdraw stake after unbonding period.
    function withdraw(bytes32 operatorId) external;

    /// @notice Slash an operator (governance only).
    function slash(bytes32 operatorId, uint256 amount, bytes calldata reason) external;

    /// @notice Get operator info.
    function getOperator(bytes32 operatorId) external view returns (
        address staker,
        uint256 stakedAmount,
        string memory endpoint,
        uint32 servicesBitmask,
        bool active,
        uint256 unstakeTime
    );

    /// @notice Get all active operator IDs.
    function getActiveOperators() external view returns (bytes32[] memory);

    /// @notice Get minimum stake requirement.
    function minStake() external view returns (uint256);
}
