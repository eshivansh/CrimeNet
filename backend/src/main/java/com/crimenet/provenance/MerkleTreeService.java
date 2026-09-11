package com.crimenet.provenance;

import com.crimenet.documents.HashService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a Merkle tree from a list of leaf hashes and computes the root.
 *
 * <p>Architecture (§8): leaf hashes → pairwise combine → intermediate nodes → Merkle root.
 * Only the root is anchored externally. Verification recomputes the leaves, rebuilds the
 * tree, and compares the root to the anchor.
 *
 * <p><b>Domain separation.</b> Leaves and internal nodes were both plain
 * {@code SHA-256(a || b)}, which makes an internal node indistinguishable from a leaf —
 * the classic second-preimage construction, where an attacker presents an internal node as
 * a leaf and produces the same root from a different event set. Leaves are now tagged
 * {@code 0x00} and nodes {@code 0x01}, following RFC 6962.
 *
 * <p><b>Odd-node duplication.</b> Duplicating the last node makes {@code [a,b,c]} and
 * {@code [a,b,c,c]} produce an identical root (CVE-2012-2459). The previous comment claimed
 * the stored {@code leafCount} prevented this, but nothing compared it on any verification
 * path. Unpaired nodes are now promoted unchanged, so the ambiguity does not arise, and
 * {@code AnchorService.verifyBatch} additionally checks the stored count.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MerkleTreeService {

    private final HashService hashService;

    /** RFC 6962 style domain separation tags. */
    private static final String LEAF_PREFIX = "00:";
    private static final String NODE_PREFIX = "01:";

    /**
     * Compute the Merkle root for a list of leaf hashes.
     */
    public String computeMerkleRoot(List<String> leafHashes) {
        if (leafHashes == null || leafHashes.isEmpty()) {
            throw new IllegalArgumentException("Cannot compute Merkle root from empty list");
        }

        // Every leaf is tagged, including the single-leaf case — returning a bare leaf as a
        // root made a one-event batch's root indistinguishable from its own event hash.
        List<String> currentLevel = new ArrayList<>(leafHashes.size());
        for (String leaf : leafHashes) {
            currentLevel.add(hashService.computeSha256(LEAF_PREFIX + leaf));
        }

        if (currentLevel.size() == 1) {
            return currentLevel.get(0);
        }

        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>((currentLevel.size() + 1) / 2);
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                if (i + 1 < currentLevel.size()) {
                    String right = currentLevel.get(i + 1);
                    nextLevel.add(hashService.computeSha256(NODE_PREFIX + left + ":" + right));
                } else {
                    // Promote the unpaired node unchanged rather than hashing it with itself.
                    nextLevel.add(left);
                }
            }
            currentLevel = nextLevel;
        }

        return currentLevel.get(0);
    }

    /**
     * Verify that a set of leaf hashes produces the expected root.
     *
     * <p>Batches anchored before domain separation was introduced carry a root computed the
     * old way. Those are still verifiable — explicitly, and logged as legacy — so that
     * historical anchors do not silently start reporting as tampering.
     */
    public boolean verifyMerkleRoot(List<String> leafHashes, String expectedRoot) {
        String computedRoot = computeMerkleRoot(leafHashes);
        if (computedRoot.equals(expectedRoot)) {
            return true;
        }

        if (legacyRoot(leafHashes).equals(expectedRoot)) {
            log.warn("MERKLE_LEGACY_ROOT: batch verified against the pre-domain-separation "
                    + "construction. Re-anchor this batch to move it onto the current scheme.");
            return true;
        }

        log.error("MERKLE_VERIFICATION_FAILED: computed={} expected={}", computedRoot, expectedRoot);
        return false;
    }

    /** The original construction, retained only to verify roots anchored before the fix. */
    private String legacyRoot(List<String> leafHashes) {
        if (leafHashes.size() == 1) {
            return leafHashes.get(0);
        }
        List<String> currentLevel = new ArrayList<>(leafHashes);
        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>();
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left;
                nextLevel.add(hashService.computeChainedHash(left, right));
            }
            currentLevel = nextLevel;
        }
        return currentLevel.get(0);
    }
}
