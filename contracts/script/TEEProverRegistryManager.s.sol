pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import {SP1TEEProverRegistry} from "../src/core/SP1TEEProverRegistry.sol";
import {ReportData} from "../src/interfaces/ISP1TEEProverRegistry.sol";

contract TEEProverRegistryManager is Script {
    address registryAddr = vm.envAddress("TEE_PROVER_REGISTRY_ADDR");
    SP1TEEProverRegistry registry = SP1TEEProverRegistry(registryAddr);

    function setUp() public {}

    function setAttestValiditySeconds(uint256 secs) public {
        vm.startBroadcast();
        registry.setAttestValiditySeconds(secs);
    }

    function setMaxBlockNumberDiff(uint256 blocks) public {
        vm.startBroadcast();
        registry.setMaxBlockNumberDiff(blocks);
    }

    function setAttestationImpl(address addr) public {
        vm.startBroadcast();
        registry.setAttestationImpl(addr);
    }

    function register(ReportData calldata reportData, bytes calldata quote) public {
        vm.startBroadcast();
        registry.register(reportData, quote);
    }

    function verifyAttestedProver(address proverAddr) public {
        vm.startBroadcast();
        console.log(registry.verifyAttestedProver(proverAddr));
    }
}