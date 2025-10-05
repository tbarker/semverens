// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {SemverResolver} from "../src/SemverResolver.sol";
import {ENS} from "ens-contracts/registry/ENS.sol";
import {INameWrapper} from "ens-contracts/wrapper/INameWrapper.sol";

/**
 * @title DeploySemverResolver
 * @notice Deployment script for SemverResolver contract
 *
 * Usage:
 *   With private key:
 *     forge script script/DeploySemverResolver.s.sol:DeploySemverResolver \
 *       --rpc-url $RPC_URL --broadcast --verify
 *
 *   With Trezor/Ledger:
 *     forge script script/DeploySemverResolver.s.sol:DeploySemverResolver \
 *       --rpc-url $RPC_URL --broadcast --verify --ledger
 *
 *   For Trezor, specify derivation path:
 *     forge script ... --ledger --hd-paths "m/44'/60'/0'/0/0"
 */
contract DeploySemverResolver is Script {
    function run() external {
        address ensRegistry = vm.envAddress("ENS_REGISTRY");
        address nameWrapper = vm.envAddress("NAME_WRAPPER");

        // When using --ledger flag, forge automatically uses hardware wallet
        // Otherwise, it uses PRIVATE_KEY from environment
        vm.startBroadcast();

        SemverResolver resolver = new SemverResolver(ENS(ensRegistry), INameWrapper(nameWrapper));

        console.log("SemverResolver deployed at:", address(resolver));

        vm.stopBroadcast();
    }

    function runLocal() external {
        vm.startBroadcast();

        // Deploy a mock ENS registry for local testing
        MockENSRegistry mockEns = new MockENSRegistry();
        console.log("Mock ENS Registry deployed at:", address(mockEns));

        // Deploy a mock NameWrapper for local testing
        MockNameWrapper mockWrapper = new MockNameWrapper();
        console.log("Mock NameWrapper deployed at:", address(mockWrapper));

        SemverResolver resolver = new SemverResolver(ENS(address(mockEns)), INameWrapper(address(mockWrapper)));
        console.log("SemverResolver deployed at:", address(resolver));

        vm.stopBroadcast();
    }
}

contract MockENSRegistry is ENS {
    mapping(bytes32 => address) public owners;
    mapping(bytes32 => address) public resolvers;
    mapping(bytes32 => uint64) public ttls;
    mapping(address => mapping(address => bool)) public operators;

    constructor() {
        // Set deployer as owner of root node
        owners[0x0] = msg.sender;
    }

    function setRecord(bytes32 node, address _owner, address _resolver, uint64 _ttl) external override {
        require(owners[node] == msg.sender || operators[owners[node]][msg.sender], "Unauthorised");
        owners[node] = _owner;
        resolvers[node] = _resolver;
        ttls[node] = _ttl;
    }

    function setSubnodeRecord(bytes32 node, bytes32 label, address _owner, address _resolver, uint64 _ttl)
        external
        override
    {
        require(owners[node] == msg.sender || operators[owners[node]][msg.sender], "Unauthorised");
        bytes32 subnode = keccak256(abi.encodePacked(node, label));
        owners[subnode] = _owner;
        resolvers[subnode] = _resolver;
        ttls[subnode] = _ttl;
        emit NewOwner(node, label, _owner);
        emit NewResolver(subnode, _resolver);
        emit NewTTL(subnode, _ttl);
    }

    function setSubnodeOwner(bytes32 node, bytes32 label, address _owner) external override returns (bytes32) {
        require(owners[node] == msg.sender || operators[owners[node]][msg.sender], "Unauthorised");
        bytes32 subnode = keccak256(abi.encodePacked(node, label));
        owners[subnode] = _owner;
        emit NewOwner(node, label, _owner);
        return subnode;
    }

    function setResolver(bytes32 node, address _resolver) external override {
        require(owners[node] == msg.sender || operators[owners[node]][msg.sender], "Unauthorised");
        resolvers[node] = _resolver;
        emit NewResolver(node, _resolver);
    }

    function setOwner(bytes32 node, address _owner) external override {
        require(owners[node] == msg.sender || operators[owners[node]][msg.sender], "Unauthorised");
        owners[node] = _owner;
        emit Transfer(node, _owner);
    }

    // forge-lint: disable-next-line(mixed-case-function)
    function setTTL(bytes32 node, uint64 ttl_) external override {
        require(owners[node] == msg.sender || operators[owners[node]][msg.sender], "Unauthorised");
        ttls[node] = ttl_;
        emit NewTTL(node, ttl_);
    }

    function setApprovalForAll(address operator, bool approved) external override {
        operators[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function owner(bytes32 node) external view override returns (address) {
        return owners[node];
    }

    function resolver(bytes32 node) external view override returns (address) {
        return resolvers[node];
    }

    function ttl(bytes32 node) external view override returns (uint64) {
        return ttls[node];
    }

    function recordExists(bytes32 node) external view override returns (bool) {
        return owners[node] != address(0);
    }

    function isApprovedForAll(address _owner, address operator) external view override returns (bool) {
        return operators[_owner][operator];
    }
}

contract MockNameWrapper {
    mapping(uint256 => address) private _owners;

    function ownerOf(uint256 id) external view returns (address) {
        return _owners[id];
    }

    function setOwner(uint256 id, address owner) external {
        _owners[id] = owner;
    }
}
