pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import {SP1MultiProof} from "../src/core/SP1MultiProof.sol";

contract MultiProofManager is Script {
    address multiProofAddr = vm.envAddress("MULTI_PROOF_ADDR");
    SP1MultiProof multiProof = SP1MultiProof(multiProofAddr);

    function setUp() public {}

    function setTEEProverRegistry(address addr) public {
        vm.startBroadcast();
        multiProof.setTEEProverRegistry(addr);
    }

    function verifyTEEProof(
        bytes memory encodedMessageBytes,
        bytes memory signature
    ) public {
        vm.startBroadcast();
        multiProof.verifyTEEProof(encodedMessageBytes, signature);
    }
}