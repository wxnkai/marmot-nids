// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title AlertRegistry
 * @notice On-chain audit log for network intrusion detection alerts.
 * @dev Only the contract owner (deployer) can write alerts via logAlert().
 *      Read methods (getAlert, getAlertCount) are public.
 *
 *      Security design:
 *      - Ownable restricts logAlert() to the deployer address, preventing
 *        unauthenticated callers from injecting fabricated alerts.
 *      - Alert data is stored as strings — field validation and
 *        sanitisation happen in the Python application layer BEFORE
 *        submission.  The contract is a append-only store.
 *      - Confidence is stored as uint256 (0–100) to avoid floating-point
 *        issues in Solidity.
 */
contract AlertRegistry is Ownable {
    struct Alert {
        string signatureId;
        string threatType;
        string severity;
        uint256 confidence;   // 0–100 (integer percentage)
        string srcIp;
        string dstIp;
        uint256 protocol;     // IANA protocol number
        uint256 timestamp;    // Unix epoch
        string description;
    }

    Alert[] private alerts;

    event AlertLogged(
        uint256 indexed index,
        string signatureId,
        string threatType,
        string severity,
        uint256 timestamp
    );

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Log a new intrusion detection alert.
     * @dev Only callable by the contract owner.
     * @param _signatureId Unique signature identifier.
     * @param _threatType Threat category slug.
     * @param _severity Severity level (low/medium/high/critical).
     * @param _confidence Confidence score 0–100.
     * @param _srcIp Source IP address.
     * @param _dstIp Destination IP address.
     * @param _protocol IANA protocol number.
     * @param _timestamp Unix epoch timestamp of the alert.
     * @param _description Human-readable alert description.
     */
    function logAlert(
        string calldata _signatureId,
        string calldata _threatType,
        string calldata _severity,
        uint256 _confidence,
        string calldata _srcIp,
        string calldata _dstIp,
        uint256 _protocol,
        uint256 _timestamp,
        string calldata _description
    ) external onlyOwner {
        alerts.push(Alert({
            signatureId: _signatureId,
            threatType: _threatType,
            severity: _severity,
            confidence: _confidence,
            srcIp: _srcIp,
            dstIp: _dstIp,
            protocol: _protocol,
            timestamp: _timestamp,
            description: _description
        }));

        emit AlertLogged(
            alerts.length - 1,
            _signatureId,
            _threatType,
            _severity,
            _timestamp
        );
    }

    /**
     * @notice Retrieve an alert by index.
     * @param _index Zero-based index into the alerts array.
     * @return All fields of the alert struct.
     */
    function getAlert(uint256 _index) external view returns (
        string memory,
        string memory,
        string memory,
        uint256,
        string memory,
        string memory,
        uint256,
        uint256,
        string memory
    ) {
        require(_index < alerts.length, "Index out of bounds");
        Alert storage a = alerts[_index];
        return (
            a.signatureId,
            a.threatType,
            a.severity,
            a.confidence,
            a.srcIp,
            a.dstIp,
            a.protocol,
            a.timestamp,
            a.description
        );
    }

    /**
     * @notice Return the number of alerts stored.
     * @return The length of the alerts array.
     */
    function getAlertCount() external view returns (uint256) {
        return alerts.length;
    }
}
