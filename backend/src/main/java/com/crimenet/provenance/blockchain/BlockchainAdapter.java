package com.crimenet.provenance.blockchain;

/**
 * Blockchain Adapter interface for anchoring and verifying Merkle roots on an immutable distributed ledger.
 */
public interface BlockchainAdapter {

    /**
     * Anchors a Merkle root for a given batch number to the blockchain.
     *
     * @param batchNumber sequential batch identifier
     * @param merkleRoot hex-encoded SHA-256 Merkle root
     * @param eventCount number of audit events in this batch
     * @return transaction hash or receipt reference
     */
    String anchorMerkleRoot(long batchNumber, String merkleRoot, int eventCount);

    /**
     * Verifies that the anchored root on-chain matches the specified Merkle root for the batch.
     *
     * @param batchNumber sequential batch identifier
     * @param merkleRoot hex-encoded SHA-256 Merkle root
     * @return true if the anchor exists on-chain and matches the root
     */
    boolean verifyAnchor(long batchNumber, String merkleRoot);

    /**
     * Returns the name of the adapter implementation (e.g. "ETHEREUM_WEB3J", "MOCK_SIMULATED").
     */
    String getAdapterType();
}
