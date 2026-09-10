package com.crimenet.provenance;

import com.crimenet.audit.AuditEvent;
import com.crimenet.audit.AuditEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Anchor Service — the ONLY code path allowed to call the anchor adapter (§2 #1).
 *
 * Periodically batches unanchored audit events into a Merkle tree,
 * computes the root, and anchors it to an external system (TSA/Ledger).
 *
 * Why this matters (§9, §24):
 *   Internal hash chaining alone proves only self-consistency. A DBA with
 *   write access could rewrite the entire chain from a point forward and
 *   recompute all subsequent hashes. The Merkle anchor to an externally
 *   controlled system is what closes this gap — any tampering will
 *   produce a root mismatch against the independently stored anchor.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnchorService {

    private final AuditEventRepository auditEventRepository;
    private final MerkleBatchRepository merkleBatchRepository;
    private final MerkleTreeService merkleTreeService;
    private final com.crimenet.provenance.blockchain.BlockchainAdapter blockchainAdapter;

    private static final int BATCH_SIZE = 100;

    /**
     * Scheduled job: every 5 minutes, batch unanchored events and anchor the Merkle root.
     */
    @Scheduled(fixedDelayString = "${crimenet.provenance.anchor-interval-ms:300000}")
    @Transactional
    public void anchorPendingEvents() {
        // Find the last anchored event ID
        long nextBatchNumber = merkleBatchRepository.findLatestBatch()
                .map(b -> b.getBatchNumber() + 1)
                .orElse(1L);

        // Get unanchored events (events created after the last batch)
        List<AuditEvent> unanchoredEvents = getUnanchoredEvents();

        if (unanchoredEvents.isEmpty()) {
            log.debug("No unanchored audit events to batch.");
            return;
        }

        // Extract event hashes as Merkle leaves
        List<String> eventHashes = unanchoredEvents.stream()
                .map(AuditEvent::getEventHash)
                .toList();

        // Build Merkle tree and compute root
        String merkleRoot = merkleTreeService.computeMerkleRoot(eventHashes);

        // Create batch record
        MerkleBatch batch = MerkleBatch.builder()
                .batchNumber(nextBatchNumber)
                .merkleRoot(merkleRoot)
                .eventCount(eventHashes.size())
                .firstEventId(unanchoredEvents.get(0).getId())
                .lastEventId(unanchoredEvents.get(unanchoredEvents.size() - 1).getId())
                .eventHashes(eventHashes)
                .anchorStatus("PENDING")
                .build();

        // Anchor externally via blockchain adapter
        try {
            String anchorReference = blockchainAdapter.anchorMerkleRoot(nextBatchNumber, merkleRoot, eventHashes.size());
            batch.setAnchorStatus("ANCHORED");
            batch.setAnchorType(blockchainAdapter.getAdapterType());
            batch.setAnchorReference(anchorReference);
            batch.setAnchorTimestamp(Instant.now());
            log.info("Merkle batch {} anchored via {}. Root: {}, Events: {}, Ref: {}",
                    nextBatchNumber, blockchainAdapter.getAdapterType(), merkleRoot, eventHashes.size(), anchorReference);
        } catch (Exception e) {
            batch.setAnchorStatus("FAILED");
            log.error("Failed to anchor Merkle batch {}: {}", nextBatchNumber, e.getMessage());
        }

        merkleBatchRepository.save(batch);
    }

    /**
     * Verify the integrity of a specific batch by:
     * 1. Re-verifying live audit trail records from the database
     * 2. Recomputing the Merkle root
     * 3. Cross-checking the root against the on-chain blockchain anchor
     */
    @Transactional(readOnly = true)
    public VerificationResult verifyBatch(long batchNumber) {
        MerkleBatch batch = merkleBatchRepository.findByBatchNumber(batchNumber)
                .orElseThrow(() -> new IllegalArgumentException("Batch not found: " + batchNumber));

        boolean liveAuditMatches = true;
        if (batch.getFirstEventId() != null && batch.getLastEventId() != null) {
            Instant from = auditEventRepository.findById(batch.getFirstEventId()).map(AuditEvent::getCreatedAt).orElse(null);
            Instant to = auditEventRepository.findById(batch.getLastEventId()).map(AuditEvent::getCreatedAt).orElse(null);
            if (from != null && to != null) {
                List<AuditEvent> liveEvents = auditEventRepository.findBetweenInstants(from, to);
                List<String> liveHashes = liveEvents.stream().map(AuditEvent::getEventHash).toList();
                if (!liveHashes.equals(batch.getEventHashes())) {
                    liveAuditMatches = false;
                    log.warn("Live audit event hashes diverge from stored batch {} hashes! Potential tampering detected.", batchNumber);
                }
            }
        }

        boolean rootMatches = merkleTreeService.verifyMerkleRoot(batch.getEventHashes(), batch.getMerkleRoot());
        boolean chainMatches = blockchainAdapter.verifyAnchor(batchNumber, batch.getMerkleRoot());

        boolean fullyValid = rootMatches && liveAuditMatches && chainMatches;
        String verdict = fullyValid ? "INTEGRITY_VERIFIED" :
                (!liveAuditMatches ? "AUDIT_TAMPERING_DETECTED" :
                (!rootMatches ? "MERKLE_ROOT_MISMATCH" : "BLOCKCHAIN_ANCHOR_MISMATCH"));

        return new VerificationResult(
                batchNumber,
                batch.getMerkleRoot(),
                batch.getAnchorReference(),
                batch.getAnchorStatus(),
                blockchainAdapter.getAdapterType(),
                liveAuditMatches,
                rootMatches,
                chainMatches,
                fullyValid,
                verdict
        );
    }

    /**
     * Verify ALL batches. Returns a summary.
     */
    @Transactional(readOnly = true)
    public List<VerificationResult> verifyAll() {
        return merkleBatchRepository.findAll().stream()
                .map(b -> verifyBatch(b.getBatchNumber()))
                .toList();
    }

    private List<AuditEvent> getUnanchoredEvents() {
        // Get the last anchored event's created_at timestamp
        Instant since = merkleBatchRepository.findLatestBatch()
                .map(b -> auditEventRepository.findById(b.getLastEventId())
                        .map(AuditEvent::getCreatedAt)
                        .orElse(Instant.EPOCH))
                .orElse(Instant.EPOCH);

        return auditEventRepository.findByCreatedAtAfterOrderByCreatedAtAsc(since,
                PageRequest.of(0, BATCH_SIZE));
    }

    public record VerificationResult(
            long batchNumber,
            String storedMerkleRoot,
            String anchorReference,
            String anchorStatus,
            String adapterType,
            boolean liveAuditValid,
            boolean merkleRootValid,
            boolean blockchainAnchorValid,
            boolean rootValid,
            String verdict
    ) {}
}
