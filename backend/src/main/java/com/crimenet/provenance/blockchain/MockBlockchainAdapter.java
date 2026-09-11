package com.crimenet.provenance.blockchain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory stand-in for a ledger, for local development without an RPC endpoint.
 *
 * <p>This is not an anchor and must never be presented as one. Its ledger is a map in the
 * same JVM as the audit chain it is supposed to independently attest, so it is written and
 * read by exactly the code it exists to check, and it is empty after every restart.
 *
 * <p>It was previously injected into {@link EthereumWeb3jAdapter} as a silent fallback,
 * which meant a production deployment with an unreachable node recorded in-memory anchors
 * as {@code ETHEREUM_WEB3J} with fabricated transaction hashes. It is now scoped out of the
 * prod profile entirely, reports its own adapter type honestly, and is only selected when
 * anchoring is explicitly disabled.
 */
@Slf4j
@Component("mockBlockchainAdapter")
@Profile("!prod")
public class MockBlockchainAdapter implements BlockchainAdapter {

    public static final String ADAPTER_TYPE = "MOCK_IN_MEMORY";

    public record AnchoredRecord(long batchNumber, String merkleRoot, int eventCount, Instant timestamp, String txHash) {}

    private final Map<Long, AnchoredRecord> ledger = new ConcurrentHashMap<>();

    @Override
    public AnchorOutcome anchorMerkleRoot(long batchNumber, String merkleRoot, int eventCount) {
        String txHash = "0xmock" + sha256(batchNumber + ":" + merkleRoot + ":" + Instant.now().toEpochMilli());
        ledger.put(batchNumber, new AnchoredRecord(batchNumber, merkleRoot, eventCount, Instant.now(), txHash));
        log.warn("[MOCK-LEDGER] Batch {} recorded in memory only — this is NOT an external anchor "
                + "and provides no tamper evidence.", batchNumber);
        return AnchorOutcome.confirmed(ADAPTER_TYPE, txHash, null);
    }

    @Override
    public VerificationOutcome verifyAnchor(long batchNumber, String merkleRoot) {
        AnchoredRecord record = ledger.get(batchNumber);
        if (record == null) {
            // After a restart every historical batch lands here. That is a property of the
            // stand-in, not evidence about the batch, so it is NOT_ANCHORED, not MISMATCH.
            return new VerificationOutcome(VerificationOutcome.Status.NOT_ANCHORED, ADAPTER_TYPE,
                    null, null, "Batch " + batchNumber + " is not in the in-memory ledger "
                    + "(which is empty after every restart)");
        }
        if (!record.merkleRoot().equalsIgnoreCase(merkleRoot)) {
            return new VerificationOutcome(VerificationOutcome.Status.MISMATCH, ADAPTER_TYPE,
                    null, record.timestamp(), "In-memory root differs from the stored batch root");
        }
        return new VerificationOutcome(VerificationOutcome.Status.VERIFIED, ADAPTER_TYPE,
                null, record.timestamp(),
                "Matches the in-memory ledger — no external attestation");
    }

    @Override
    public String getAdapterType() {
        return ADAPTER_TYPE;
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(input.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
