// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title QPLRegistry
/// @notice On-chain registry of QPL operators and their capabilities.
/// @dev Read by SDK clients for operator discovery. Updated by staking contract.
contract QPLRegistry {
    // ─── Types ─────────────────────────────────────────────────────────

    struct OperatorInfo {
        bytes32 operatorId;
        address staker;
        string endpoint;
        uint32 servicesBitmask;
        uint256 registeredAt;
        bool active;
    }

    // ─── State ─────────────────────────────────────────────────────────

    /// @notice QPLStaking contract address (only it can update registry).
    address public staking;

    /// @notice Governance address.
    address public governance;

    /// @notice Operator ID => info.
    mapping(bytes32 => OperatorInfo) public operatorInfo;

    /// @notice All registered operator IDs (including inactive).
    bytes32[] public allOperators;

    /// @notice Service bitmask constants.
    uint32 public constant SERVICE_SIGNING = 1;
    uint32 public constant SERVICE_PROVING = 2;
    uint32 public constant SERVICE_SETTLEMENT = 4;
    uint32 public constant SERVICE_YIELD = 8;
    uint32 public constant SERVICE_RWA = 16;

    // ─── Events ────────────────────────────────────────────────────────

    event OperatorRegistered(bytes32 indexed operatorId, address indexed staker, string endpoint);
    event OperatorUpdated(bytes32 indexed operatorId, string endpoint, uint32 servicesBitmask);
    event OperatorDeactivated(bytes32 indexed operatorId);

    // ─── Modifiers ─────────────────────────────────────────────────────

    modifier onlyStaking() {
        require(msg.sender == staking, "QPLRegistry: not staking contract");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "QPLRegistry: not governance");
        _;
    }

    // ─── Constructor ───────────────────────────────────────────────────

    constructor(address _staking, address _governance) {
        staking = _staking;
        governance = _governance;
    }

    // ─── External Functions ────────────────────────────────────────────

    /// @notice Register a new operator (called by staking contract).
    function register(
        bytes32 operatorId,
        address staker,
        string calldata endpoint,
        uint32 servicesBitmask
    ) external onlyStaking {
        require(operatorInfo[operatorId].staker == address(0), "QPLRegistry: already registered");

        operatorInfo[operatorId] = OperatorInfo({
            operatorId: operatorId,
            staker: staker,
            endpoint: endpoint,
            servicesBitmask: servicesBitmask,
            registeredAt: block.timestamp,
            active: true
        });

        allOperators.push(operatorId);
        emit OperatorRegistered(operatorId, staker, endpoint);
    }

    /// @notice Update operator endpoint or services (by operator owner).
    function update(
        bytes32 operatorId,
        string calldata endpoint,
        uint32 servicesBitmask
    ) external {
        OperatorInfo storage info = operatorInfo[operatorId];
        require(info.staker == msg.sender, "QPLRegistry: not owner");
        require(info.active, "QPLRegistry: not active");

        info.endpoint = endpoint;
        info.servicesBitmask = servicesBitmask;

        emit OperatorUpdated(operatorId, endpoint, servicesBitmask);
    }

    /// @notice Deactivate an operator (called by staking contract on unstake).
    function deactivate(bytes32 operatorId) external onlyStaking {
        operatorInfo[operatorId].active = false;
        emit OperatorDeactivated(operatorId);
    }

    // ─── View Functions ────────────────────────────────────────────────

    /// @notice Get all operators that support a given service.
    function getOperatorsByService(uint32 serviceBit) external view returns (bytes32[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < allOperators.length; i++) {
            OperatorInfo storage info = operatorInfo[allOperators[i]];
            if (info.active && (info.servicesBitmask & serviceBit) != 0) {
                count++;
            }
        }

        bytes32[] memory result = new bytes32[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < allOperators.length; i++) {
            OperatorInfo storage info = operatorInfo[allOperators[i]];
            if (info.active && (info.servicesBitmask & serviceBit) != 0) {
                result[idx++] = allOperators[i];
            }
        }

        return result;
    }

    /// @notice Get total number of registered operators.
    function totalOperators() external view returns (uint256) {
        return allOperators.length;
    }

    /// @notice Get operator endpoint for SDK discovery.
    function getEndpoint(bytes32 operatorId) external view returns (string memory) {
        return operatorInfo[operatorId].endpoint;
    }

    /// @notice Update staking contract address (governance only).
    function setStaking(address _staking) external onlyGovernance {
        staking = _staking;
    }
}
