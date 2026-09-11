package com.crimenet.provenance;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface MerkleBatchRepository extends JpaRepository<MerkleBatch, UUID> {

    @Query("SELECT mb FROM MerkleBatch mb ORDER BY mb.batchNumber DESC LIMIT 1")
    Optional<MerkleBatch> findLatestBatch();

    /**
     * The watermark for "what still needs anchoring" must come from the last batch that
     * actually anchored. Deriving it from the latest batch of any status meant one RPC
     * outage advanced the watermark past events that were never anchored, permanently.
     */
    @Query("SELECT mb FROM MerkleBatch mb WHERE mb.anchorStatus = 'ANCHORED' ORDER BY mb.batchNumber DESC LIMIT 1")
    Optional<MerkleBatch> findLatestAnchoredBatch();

    /** Batches awaiting a retry. */
    java.util.List<MerkleBatch> findByAnchorStatusInOrderByBatchNumberAsc(java.util.Collection<String> statuses);

    long countByAnchorStatusIn(java.util.Collection<String> statuses);

    Optional<MerkleBatch> findByBatchNumber(long batchNumber);

    /** Serialises batch-number allocation across instances. */
    @Query(value = "SELECT pg_advisory_xact_lock(hashtext('merkle_batch_allocation'))", nativeQuery = true)
    void acquireBatchLock();
}
