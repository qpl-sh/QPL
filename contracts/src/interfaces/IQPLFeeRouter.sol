// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IQPLFeeRouter
/// @notice Interface for the QPL fee collection and distribution contract.
interface IQPLFeeRouter {
    /// @notice Emitted when a fee is paid for a service request.
    event FeePaid(
        bytes32 indexed quoteId,
        bytes32 indexed operatorId,
        address indexed payer,
        uint256 amount
    );

    /// @notice Emitted when fees are distributed to participants.
    event FeeDistributed(
        bytes32 indexed quoteId,
        uint256 coordinatorAmount,
        uint256 participantAmount,
        uint256 treasuryAmount
    );

    /// @notice Pay fee for a QPL service request.
    /// @param quoteId The fee quote ID from the operator.
    /// @param operatorId The coordinator operator ID.
    function payFee(bytes32 quoteId, bytes32 operatorId) external payable;

    /// @notice Distribute collected fees for a completed request.
    /// @param quoteId The quote ID.
    /// @param coordinator The coordinator operator's staker address.
    /// @param participants Array of participant staker addresses.
    function distributeFee(
        bytes32 quoteId,
        address coordinator,
        address[] calldata participants
    ) external;

    /// @notice Get the fee split configuration.
    function getFeeSplit() external view returns (
        uint8 coordinatorPct,
        uint8 participantPct,
        uint8 treasuryPct
    );

    /// @notice Get treasury address.
    function treasury() external view returns (address);

    /// @notice Check if a quote has been paid.
    function isPaid(bytes32 quoteId) external view returns (bool);
}
