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
 * Architecture (§8):
 *   Leaf hashes → pairwise combine → intermediate nodes → Merkle Root
 *   Only the root is anchored externally.
 *   Verification: recompute leaves → rebuild tree → compare root to anchor.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MerkleTreeService {

    private final HashService hashService;

    /**
     * Compute the Merkle root for a list of leaf hashes.
     * If the list has an odd number of elements, the last element is duplicated.
     */
    public String computeMerkleRoot(List<String> leafHashes) {
        if (leafHashes == null || leafHashes.isEmpty()) {
            throw new IllegalArgumentException("Cannot compute Merkle root from empty list");
        }
        if (leafHashes.size() == 1) {
            return leafHashes.get(0);
        }

        List<String> currentLevel = new ArrayList<>(leafHashes);

        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>();
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                // If odd number of nodes, duplicate last
                String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left;
                String pairHash = hashService.computeChainedHash(left, right);
                nextLevel.add(pairHash);
            }
            currentLevel = nextLevel;
        }

        return currentLevel.get(0);
    }

    /**
     * Verify that a given set of leaf hashes produces the expected Merkle root.
     */
    public boolean verifyMerkleRoot(List<String> leafHashes, String expectedRoot) {
        String computedRoot = computeMerkleRoot(leafHashes);
        boolean matches = computedRoot.equals(expectedRoot);
        if (!matches) {
            log.error("MERKLE_VERIFICATION_FAILED: computed={} expected={}", computedRoot, expectedRoot);
        }
        return matches;
    }
}
