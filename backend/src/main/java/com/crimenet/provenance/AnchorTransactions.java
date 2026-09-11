package com.crimenet.provenance;

import com.crimenet.audit.AuditEvent;
import com.crimenet.audit.AuditEventRepository;
import com.crimenet.provenance.blockchain.BlockchainAdapter.AnchorOutcome;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The database half of anchoring, kept in its own bean on purpose.
 *
 * <p>{@code @Transactional} is applied by a proxy, so a call from one method of a bean to
 * another method of the same bean bypasses it entirely — the annotation silently does
 * nothing. Anchoring needs several short transactions around a network call, so those
 * transactions live here and {@link AnchorService} calls them through the proxy.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class AnchorTransactions {

    private final AuditEventRepository auditEventRepository;
    private final MerkleBatchRepository merkleBatchRepository;
    private final MerkleTreeService merkleTreeService;

    private static final int BATCH_SIZE = 100;
    static final List<String> RETRYABLE = List.of("PENDING", "FAILED");

    /**
     * Reserve the batch number and persist the batch as PENDING before anything leaves the
     * process, so a crash mid-anchor leaves a retryable row rather than an orphaned anchor.
     */
    @Transactional
    MerkleBatch createPendingBatch() {
        // Two instances computing nextBatchNumber concurrently both picked the same number;
        // one then died on the unique constraint, or both anchored overlapping event sets.
        merkleBatchRepository.acquireBatchLock();

        List<AuditEvent> unanchored = getUnanchoredEvents();
        if (unanchored.isEmpty()) {
            log.debug("No unanchored audit events to batch.");
            return null;
        }

        long nextBatchNumber = merkleBatchRepository.findLatestBatch()
                .map(b -> b.getBatchNumber() + 1)
                .orElse(1L);

        List<String> eventHashes = unanchored.stream().map(AuditEvent::getEventHash).toList();

        MerkleBatch batch = MerkleBatch.builder()
                .batchNumber(nextBatchNumber)
                .merkleRoot(merkleTreeService.computeMerkleRoot(eventHashes))
                .eventCount(eventHashes.size())
                .firstEventId(unanchored.get(0).getId())
                .lastEventId(unanchored.get(unanchored.size() - 1).getId())
                .eventHashes(eventHashes)
                .anchorStatus("PENDING")
                .build();

        return merkleBatchRepository.save(batch);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void recordAnchorOutcome(long batchNumber, AnchorOutcome outcome) {
        MerkleBatch batch = merkleBatchRepository.findByBatchNumber(batchNumber).orElse(null);
        if (batch == null) {
            log.error("Batch {} vanished between anchoring and recording the outcome", batchNumber);
            return;
        }

        // anchorType records the adapter that actually served the call. It used to record
        // the adapter that was configured, even when a fallback answered instead.
        batch.setAnchorType(outcome.adapterType());
        batch.setAnchorReference(outcome.txHash());

        if (outcome.anchored()) {
            batch.setAnchorStatus("ANCHORED");
            batch.setAnchorTimestamp(Instant.now());
            log.info("Merkle batch {} anchored via {} — root {}, {} events, ref {}",
                    batchNumber, outcome.adapterType(), batch.getMerkleRoot(),
                    batch.getEventCount(), outcome.txHash());
        } else {
            batch.setAnchorStatus("FAILED");
            log.error("ANCHOR_FAILED batch {} via {}: {}. The batch stays retryable and the "
                            + "watermark does not advance past it.",
                    batchNumber, outcome.adapterType(), outcome.failureReason());
        }

        merkleBatchRepository.save(batch);
    }

    @Transactional(readOnly = true)
    List<MerkleBatch> findRetryableBatches() {
        return merkleBatchRepository.findByAnchorStatusInOrderByBatchNumberAsc(RETRYABLE);
    }

    @Transactional(readOnly = true)
    long unanchoredBatchCount() {
        return merkleBatchRepository.countByAnchorStatusIn(RETRYABLE);
    }

    /**
     * Events after the (createdAt, id) watermark of the last <em>successfully anchored</em>
     * batch. Both halves of that matter: a FAILED batch must not move the watermark, and a
     * plain timestamp comparison drops events that tie with the boundary event.
     */
    private List<AuditEvent> getUnanchoredEvents() {
        Optional<MerkleBatch> lastAnchored = merkleBatchRepository.findLatestAnchoredBatch();

        if (lastAnchored.isEmpty()) {
            return auditEventRepository.findAfterTuple(
                    Instant.EPOCH, new UUID(0L, 0L), PageRequest.of(0, BATCH_SIZE));
        }

        Optional<AuditEvent> watermark = auditEventRepository.findById(lastAnchored.get().getLastEventId());
        if (watermark.isEmpty()) {
            log.error("Watermark event {} for anchored batch {} is missing from the audit trail",
                    lastAnchored.get().getLastEventId(), lastAnchored.get().getBatchNumber());
            return List.of();
        }

        return auditEventRepository.findAfterTuple(
                watermark.get().getCreatedAt(), watermark.get().getId(), PageRequest.of(0, BATCH_SIZE));
    }
}
