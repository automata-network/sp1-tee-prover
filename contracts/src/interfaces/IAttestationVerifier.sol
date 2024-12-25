//SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

enum ZkCoProcessorType {
    Unknown,
    RiscZero,
    Succinct
}

interface IAttestationVerifier {
    function verifyAndAttestOnChain(
        bytes calldata rawQuote
    ) external returns (bool success, bytes memory output);

    function verifyAndAttestWithZKProof(
        bytes calldata output, 
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (bool success, bytes memory verifiedOutput);
}
