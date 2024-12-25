//SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

struct ReportData {
    uint256 referenceBlockNumber;
    bytes32 referenceBlockHash;
    address proverAddress;
}

interface ISP1TEEProverRegistry {
    function register(ReportData calldata _data, bytes calldata _report) external;

    function verifyAttestedProver(address proverAddr) external view returns (bool);
}
