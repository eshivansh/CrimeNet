package com.crimenet.documents;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 hash computation for document integrity.
 */
@Service
public class HashService {

    /**
     * Compute SHA-256 hash of raw byte content.
     */
    public String computeSha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Compute SHA-256 hash of a string (used for audit event hash chains).
     */
    public String computeSha256(String content) {
        return computeSha256(content.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute a chained hash: SHA-256(previousHash + payload).
     */
    public String computeChainedHash(String previousHash, String payload) {
        String input = (previousHash != null ? previousHash : "") + payload;
        return computeSha256(input);
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
