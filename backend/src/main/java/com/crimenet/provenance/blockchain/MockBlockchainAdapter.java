package com.crimenet.provenance.blockchain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory simulated blockchain adapter used when external RPC node is unavailable.
 */
@Slf4j
@Component("mockBlockchainAdapter")
public class MockBlockchainAdapter implements BlockchainAdapter {

    public record AnchoredRecord(long batchNumber, String merkleRoot, int eventCount, Instant timestamp, String txHash) {}

    private final Map<Long, AnchoredRecord> ledger = new ConcurrentHashMap<>();

    @Override
    public String anchorMerkleRoot(long batchNumber, String merkleRoot, int eventCount) {
        String txInput = batchNumber + ":" + merkleRoot + ":" + Instant.now().toEpochMilli();
        String txHash = "0x" + sha256(txInput);
        AnchoredRecord record = new AnchoredRecord(batchNumber, merkleRoot, eventCount, Instant.now(), txHash);
        ledger.put(batchNumber, record);
        log.info("[MOCK-LEDGER] Anchored batch {} with root {} -> txHash: {}", batchNumber, merkleRoot, txHash);
        return txHash;
    }

    @Override
    public boolean verifyAnchor(long batchNumber, String merkleRoot) {
        AnchoredRecord record = ledger.get(batchNumber);
        if (record == null) {
            log.warn("[MOCK-LEDGER] Verification failed: batch {} not found on simulated ledger", batchNumber);
            return false;
        }
        boolean matches = record.merkleRoot().equalsIgnoreCase(merkleRoot);
        log.info("[MOCK-LEDGER] Batch {} verification result: {}", batchNumber, matches);
        return matches;
    }

    @Override
    public String getAdapterType() {
        return "MOCK_SIMULATED";
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
