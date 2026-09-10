// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title DocumentProvenanceAnchor
 * @dev Anchors Merkle roots of CrimeNet audit logs and document hash chains.
 * Provides immutable on-chain proof of existence and tamper-evident history.
 */
contract DocumentProvenanceAnchor {

    struct MerkleAnchor {
        uint256 batchNumber;
        bytes32 merkleRoot;
        uint256 eventCount;
        uint256 timestamp;
        address anchoredBy;
    }

    address public owner;
    
    // batchNumber => MerkleAnchor
    mapping(uint256 => MerkleAnchor) public anchors;
    
    // merkleRoot => batchNumber
    mapping(bytes32 => uint256) public rootToBatch;

    event MerkleRootAnchored(
        uint256 indexed batchNumber,
        bytes32 indexed merkleRoot,
        uint256 eventCount,
        uint256 timestamp,
        address indexed anchoredBy
    );

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "DocumentProvenanceAnchor: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "DocumentProvenanceAnchor: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /**
     * @dev Anchor a new Merkle root representing an audit batch or document provenance cycle.
     */
    function anchorRoot(
        uint256 batchNumber,
        bytes32 merkleRoot,
        uint256 eventCount
    ) external onlyOwner {
        require(batchNumber > 0, "DocumentProvenanceAnchor: batch number must be > 0");
        require(merkleRoot != bytes32(0), "DocumentProvenanceAnchor: merkle root cannot be zero");
        require(anchors[batchNumber].timestamp == 0, "DocumentProvenanceAnchor: batch already anchored");

        MerkleAnchor memory newAnchor = MerkleAnchor({
            batchNumber: batchNumber,
            merkleRoot: merkleRoot,
            eventCount: eventCount,
            timestamp: block.timestamp,
            anchoredBy: msg.sender
        });

        anchors[batchNumber] = newAnchor;
        rootToBatch[merkleRoot] = batchNumber;

        emit MerkleRootAnchored(
            batchNumber,
            merkleRoot,
            eventCount,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @dev Verify if a given batch number and Merkle root match what was anchored on-chain.
     */
    function verifyRoot(
        uint256 batchNumber,
        bytes32 merkleRoot
    ) external view returns (bool isValid, uint256 timestamp, address anchoredBy) {
        MerkleAnchor memory a = anchors[batchNumber];
        if (a.timestamp > 0 && a.merkleRoot == merkleRoot) {
            return (true, a.timestamp, a.anchoredBy);
        }
        return (false, 0, address(0));
    }

    /**
     * @dev Retrieve anchor metadata for a given batch.
     */
    function getAnchor(uint256 batchNumber) external view returns (
        uint256 bNumber,
        bytes32 mRoot,
        uint256 eCount,
        uint256 tStamp,
        address aBy
    ) {
        MerkleAnchor memory a = anchors[batchNumber];
        require(a.timestamp > 0, "DocumentProvenanceAnchor: batch not found");
        return (a.batchNumber, a.merkleRoot, a.eventCount, a.timestamp, a.anchoredBy);
    }
}
