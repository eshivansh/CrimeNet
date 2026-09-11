package com.crimenet.provenance;

import com.crimenet.audit.AuditEvent;
import com.crimenet.audit.AuditEventRepository;
import com.crimenet.provenance.blockchain.BlockchainAdapter;
import com.crimenet.provenance.blockchain.BlockchainAdapter.AnchorOutcome;
import com.crimenet.provenance.blockchain.BlockchainAdapter.VerificationOutcome;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Anchor Service — the ONLY code path allowed to call the anchor adapter (§2 #1).
 *
 * <p>Periodically batches unanchored audit events into a Merkle tree, computes the root,
 * and anchors it externally.
 *
 * <p>Why this matters (§9, §24): internal hash chaining alone proves only self-consistency.
 * A DBA with write access could rewrite the chain from a point forward and recompute every
 * subsequent hash. The external anchor is what closes that gap.
 *
 * <p>Three defects made that guarantee leak silently, and the shape of this class follows
 * from fixing them. A failed anchor used to still advance the watermark, so one RPC outage
 * permanently removed those events from all anchoring with no retry and no alert. The
 * batch row was saved after the RPC, so a commit failure left an on-chain anchor for a
 * batch number the database would reissue. And the RPC ran inside the transaction, holding
 * a pooled connection across a network round trip that can take a minute.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnchorService {

    private final AuditEventRepository auditEventRepository;
    private final MerkleBatchRepository merkleBatchRepository;
    private final MerkleTreeService merkleTreeService;
    private final BlockchainAdapter blockchainAdapter;
    private final AnchorTransactions transactions;

    /**
     * Scheduled job: batch unanchored events, then anchor.
     *
     * <p>Deliberately not {@code @Transactional} — it runs short transactions through
     * {@link AnchorTransactions} around the network call rather than holding one open
     * across it, which previously pinned a pooled connection for the whole RPC round trip.
     */
    @Scheduled(fixedDelayString = "${crimenet.provenance.anchor-interval-ms:300000}")
    public void anchorPendingEvents() {
        MerkleBatch batch = transactions.createPendingBatch();
        if (batch != null) {
            anchorBatch(batch);
        }
        retryFailedBatches();
    }

    /** Anchors an already-persisted PENDING batch. The RPC happens outside any transaction. */
    public void anchorBatch(MerkleBatch batch) {
        AnchorOutcome outcome = blockchainAdapter.anchorMerkleRoot(
                batch.getBatchNumber(), batch.getMerkleRoot(), batch.getEventCount());
        transactions.recordAnchorOutcome(batch.getBatchNumber(), outcome);
    }

    /**
     * Re-attempt batches that never anchored. Without this, a transient outage was a
     * permanent hole in the tamper-evidence record.
     */
    public void retryFailedBatches() {
        for (MerkleBatch batch : transactions.findRetryableBatches()) {
            log.info("Retrying anchor for batch {} (status {})", batch.getBatchNumber(), batch.getAnchorStatus());
            anchorBatch(batch);
        }
    }

    /** Number of batches that have not anchored — surfaced as a health indicator. */
    public long unanchoredBatchCount() {
        return transactions.unanchoredBatchCount();
    }

    /**
     * Verify a batch by re-reading the live audit rows it covered, recomputing the root,
     * and cross-checking against the external anchor.
     */
    @Transactional(readOnly = true)
    public VerificationResult verifyBatch(long batchNumber) {
        MerkleBatch batch = merkleBatchRepository.findByBatchNumber(batchNumber)
                .orElseThrow(() -> new IllegalArgumentException("Batch not found: " + batchNumber));

        boolean liveAuditMatches = true;
        if (batch.getFirstEventId() != null && batch.getLastEventId() != null) {
            Optional<AuditEvent> first = auditEventRepository.findById(batch.getFirstEventId());
            Optional<AuditEvent> last = auditEventRepository.findById(batch.getLastEventId());
            if (first.isPresent() && last.isPresent()) {
                List<AuditEvent> liveEvents = auditEventRepository.findInTupleRange(
                        first.get().getCreatedAt(), first.get().getId(),
                        last.get().getCreatedAt(), last.get().getId());
                List<String> liveHashes = liveEvents.stream().map(AuditEvent::getEventHash).toList();
                if (!liveHashes.equals(batch.getEventHashes())) {
                    liveAuditMatches = false;
                    log.warn("AUDIT_TAMPERING_SUSPECTED: live event hashes diverge from stored batch {}",
                            batchNumber);
                }
            } else {
                // A boundary event being gone is itself tampering evidence.
                liveAuditMatches = false;
                log.warn("AUDIT_BOUNDARY_MISSING: batch {} references an audit event that no longer exists",
                        batchNumber);
            }
        }

        // The odd-node duplication in MerkleTreeService makes [a,b,c] and [a,b,c,c] produce
        // the same root, so the stored count is checked against the stored hashes.
        boolean countMatches = batch.getEventHashes() != null
                && batch.getEventCount() == batch.getEventHashes().size();
        if (!countMatches) {
            log.warn("BATCH_COUNT_MISMATCH: batch {} claims {} events but stores {} hashes",
                    batchNumber, batch.getEventCount(),
                    batch.getEventHashes() == null ? 0 : batch.getEventHashes().size());
        }

        boolean rootMatches = merkleTreeService.verifyMerkleRoot(batch.getEventHashes(), batch.getMerkleRoot());
        VerificationOutcome chain = blockchainAdapter.verifyAnchor(batchNumber, batch.getMerkleRoot());

        boolean fullyValid = rootMatches && liveAuditMatches && countMatches && chain.valid();

        // An unreachable node is not tamper evidence, and must not be reported as though
        // it were. Each failure mode now names itself.
        String verdict;
        if (fullyValid) {
            verdict = "INTEGRITY_VERIFIED";
        } else if (!liveAuditMatches) {
            verdict = "AUDIT_TAMPERING_DETECTED";
        } else if (!countMatches) {
            verdict = "BATCH_COUNT_MISMATCH";
        } else if (!rootMatches) {
            verdict = "MERKLE_ROOT_MISMATCH";
        } else {
            verdict = switch (chain.status()) {
                case MISMATCH -> "BLOCKCHAIN_ANCHOR_MISMATCH";
                case NOT_ANCHORED -> "NOT_ANCHORED";
                case UNAVAILABLE -> "VERIFICATION_UNAVAILABLE";
                case VERIFIED -> "INTEGRITY_VERIFIED";
            };
        }

        return new VerificationResult(
                batchNumber,
                batch.getMerkleRoot(),
                batch.getAnchorReference(),
                batch.getAnchorStatus(),
                chain.adapterType(),
                chain.anchoredBy(),
                chain.anchoredAt(),
                liveAuditMatches,
                rootMatches,
                chain.valid(),
                fullyValid,
                verdict,
                chain.detail()
        );
    }

    @Transactional(readOnly = true)
    public List<VerificationResult> verifyAll() {
        return merkleBatchRepository.findAll().stream()
                .map(b -> verifyBatch(b.getBatchNumber()))
                .toList();
    }

    public record VerificationResult(
            long batchNumber,
            String storedMerkleRoot,
            String anchorReference,
            String anchorStatus,
            String adapterType,
            String anchoredBy,
            Instant anchoredAt,
            boolean liveAuditValid,
            boolean merkleRootValid,
            boolean blockchainAnchorValid,
            boolean rootValid,
            String verdict,
            String detail
    ) {}
}
