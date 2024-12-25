// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {IAttestationVerifier} from "../interfaces/IAttestationVerifier.sol";
import {ISP1TEEProverRegistry, ReportData} from "../interfaces/ISP1TEEProverRegistry.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract SP1TEEProverRegistry is OwnableUpgradeable, ISP1TEEProverRegistry {
    error INVALID_REPORT();
    error INVALID_REPORT_DATA();

    mapping(bytes32 => bool) public attestedReports;
    mapping(address => uint256) public attestedProvers; // prover's pubkey => attestedTime

    uint256 public attestValiditySeconds = 3600;
    uint256 public maxBlockNumberDiff = 100;

    IAttestationVerifier public dcapAttestationVerifier;

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        address _attestationAddr,
        uint256 _maxBlockNumberDiff,
        uint256 _attestValiditySeconds
    ) public initializer {
        dcapAttestationVerifier = IAttestationVerifier(_attestationAddr);
        maxBlockNumberDiff = _maxBlockNumberDiff;
        attestValiditySeconds = _attestValiditySeconds;
        _transferOwnership(_initialOwner);
    }

    function reinitialize(
        uint8 i,
        address _initialOwner,
        address _attestationAddr,
        uint256 _maxBlockNumberDiff,
        uint256 _attestValiditySeconds
    ) public reinitializer(i) {
        dcapAttestationVerifier = IAttestationVerifier(_attestationAddr);
        maxBlockNumberDiff = _maxBlockNumberDiff;
        attestValiditySeconds = _attestValiditySeconds;
        _transferOwnership(_initialOwner);
    }

    function setMaxBlockNumberDiff(
        uint256 _maxBlockNumberDiff
    ) public onlyOwner {
        maxBlockNumberDiff = _maxBlockNumberDiff;
    }

    function setAttestationImpl(address _attestationAddr) public onlyOwner {
        dcapAttestationVerifier = IAttestationVerifier(_attestationAddr);
    }

    function setAttestValiditySeconds(uint256 val) public onlyOwner {
        attestValiditySeconds = val;
    }

    function verifyAttestation(
        bytes calldata _report
    ) public returns (bytes memory) {
        (bool succ, bytes memory output) = dcapAttestationVerifier.verifyAndAttestOnChain(_report);
        if (!succ) revert INVALID_REPORT();
        if (output.length < 64) revert INVALID_REPORT_DATA();

        // tee = output[2:6]
        bytes4 tee;
        assembly {
            let start := add(add(output, 0x20), 2)
            tee := mload(start)
        }

        bytes memory reportData = new bytes(64);
        if (tee == 0x00000000) {
            // sgx, reportData = output[333:397]
            assembly {
                let start := add(add(output, 0x20), 333) // 13 + 384 - 64
                mstore(add(reportData, 0x20), mload(start))
                mstore(add(reportData, 0x40), mload(add(start, 32)))
            }
        } else {
            // tdx, reportData = output[533:597]
            assembly {
                let start := add(add(output, 0x20), 533) // 13 + 584 - 64
                mstore(add(reportData, 0x20), mload(start))
                mstore(add(reportData, 0x40), mload(add(start, 32)))
            }
        }
        return reportData;
    }

    function register(
        ReportData calldata _data,
        bytes calldata _report
    ) public {
        checkBlockNumber(_data.referenceBlockNumber, _data.referenceBlockHash);

        bytes32 reportHash = keccak256(_report);
        require(!attestedReports[reportHash], "report is already used");

        (bytes memory reportData) = verifyAttestation(_report);

        (bytes32 proverBytes, bytes32 reportDataHash) = splitBytes64(reportData);
        bytes32 dataHash = keccak256(abi.encode(_data));
        require(dataHash == reportDataHash, "report data hash mismatch");
        address proverAddr = address(uint160(uint256(proverBytes)));
        require(proverAddr == _data.proverAddress, "prover address mismatch");

        attestedReports[reportHash] = true;
        attestedProvers[proverAddr] = block.timestamp;
    }

    function verifyAttestedProver(
        address proverAddr
    ) public view returns (bool) {
        return attestedProvers[proverAddr] + attestValiditySeconds > block.timestamp;
    }

    function splitBytes64(
        bytes memory b
    ) private pure returns (bytes32, bytes32) {
        require(b.length >= 64, "Bytes array too short");

        bytes32 x;
        bytes32 y;
        assembly {
            x := mload(add(b, 32))
            y := mload(add(b, 64))
        }
        return (x, y);
    }

    // this function will make sure the attestation report generated in recent ${maxBlockNumberDiff} blocks
    function checkBlockNumber(
        uint256 blockNumber,
        bytes32 blockHash
    ) private view {
        require(blockNumber < block.number, "invalid block number");
        require(
            block.number - blockNumber < maxBlockNumberDiff,
            "block number out-of-date"
        );
        require(blockhash(blockNumber) == blockHash, "block number mismatch");
    }
}
