// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Ownable} from "solady/auth/Ownable.sol";
import {ISP1TEEProverRegistry} from "../interfaces/ISP1TEEProverRegistry.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

contract SP1MultiProof is Ownable {
    using ECDSA for bytes32;

    error Invalid_TEE_Signer(address recovered);

    ISP1TEEProverRegistry public teeProverRegistry;

    constructor() {
        _initializeOwner(msg.sender);
    }

    function setTEEProverRegistry(address regitry) external onlyOwner {
        teeProverRegistry = ISP1TEEProverRegistry(regitry);
    }

    function verifyTEEProof(
        bytes memory encodedMessageBytes,
        bytes memory signature
    ) public view {
        // verify signature
        bytes32 digest = keccak256(encodedMessageBytes);
        address recovered = digest.recover(signature);
        if (!teeProverRegistry.verifyAttestedProver(recovered)) {
            revert Invalid_TEE_Signer(recovered);
        }
    }
}
