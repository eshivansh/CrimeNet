package com.crimenet.provenance.blockchain;

import java.time.Instant;

/**
 * Anchors and verifies Merkle roots on an external, independently controlled ledger.
 *
 * <p>Both methods used to return a bare {@code String}/{@code boolean}, which made two
 * different failures indistinguishable from two different successes: a transaction hash
 * from a real chain looked identical to one minted by an in-memory stand-in, and a node
 * being unreachable looked identical to a root that genuinely did not match. The anchor
 * is the only thing standing between this system and a DBA who rewrites the audit chain,
 * so the contract has to say which of those actually happened.
 */
public interface BlockchainAdapter {

    /**
     * Anchor a Merkle root for a batch.
     *
     * @return what actually happened, including which adapter served the call
     */
    AnchorOutcome anchorMerkleRoot(long batchNumber, String merkleRoot, int eventCount);

    /**
     * Verify that the on-chain anchor for this batch matches the supplied root.
     *
     * @return the verification status, distinguishing a mismatch from an unreachable node
     */
    VerificationOutcome verifyAnchor(long batchNumber, String merkleRoot);

    /** Name of this adapter implementation, e.g. {@code ETHEREUM_WEB3J}. */
    String getAdapterType();

    /**
     * The result of an anchoring attempt.
     *
     * @param anchored      true only when the transaction was mined and confirmed
     * @param adapterType   the adapter that actually served this call, never an aspiration
     * @param txHash        transaction hash, present whether or not it confirmed
     * @param blockNumber   the block it was mined in, null when unconfirmed
     * @param failureReason why it did not anchor, null on success
     */
    record AnchorOutcome(
            boolean anchored,
            String adapterType,
            String txHash,
            Long blockNumber,
            String failureReason
    ) {
        public static AnchorOutcome confirmed(String adapterType, String txHash, Long blockNumber) {
            return new AnchorOutcome(true, adapterType, txHash, blockNumber, null);
        }

        public static AnchorOutcome failed(String adapterType, String txHash, String reason) {
            return new AnchorOutcome(false, adapterType, txHash, null, reason);
        }
    }

    /**
     * The result of a verification attempt.
     *
     * @param status      what the ledger said
     * @param adapterType the adapter that answered
     * @param anchoredBy  the address that wrote the anchor, so an anchor written by a
     *                    stolen key is not silently accepted as valid
     * @param anchoredAt  the on-chain timestamp, null when not anchored
     * @param detail      human-readable context for the status
     */
    record VerificationOutcome(
            Status status,
            String adapterType,
            String anchoredBy,
            Instant anchoredAt,
            String detail
    ) {
        public enum Status {
            /** The on-chain root matches, written by the expected anchoring address. */
            VERIFIED,
            /** An anchor exists for this batch but the root differs — real tamper evidence. */
            MISMATCH,
            /** No anchor exists for this batch number. */
            NOT_ANCHORED,
            /** The ledger could not be reached. Says nothing about the root either way. */
            UNAVAILABLE
        }

        public boolean valid() {
            return status == Status.VERIFIED;
        }

        public static VerificationOutcome unavailable(String adapterType, String detail) {
            return new VerificationOutcome(Status.UNAVAILABLE, adapterType, null, null, detail);
        }
    }
}
