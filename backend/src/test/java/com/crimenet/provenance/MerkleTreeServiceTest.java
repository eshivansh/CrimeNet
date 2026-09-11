package com.crimenet.provenance;

import com.crimenet.documents.HashService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The Merkle construction is what the whole tamper-evidence claim reduces to, and it had
 * no test of any kind. These cover the two properties that were actually broken.
 */
class MerkleTreeServiceTest {

    private final HashService hashService = new HashService();
    private final MerkleTreeService merkle = new MerkleTreeService(hashService);

    private static final String A = "aa".repeat(32);
    private static final String B = "bb".repeat(32);
    private static final String C = "cc".repeat(32);
    private static final String D = "dd".repeat(32);

    @Test
    @DisplayName("odd leaf counts are not malleable: [a,b,c] and [a,b,c,c] differ")
    void oddLeafDuplicationIsNotMalleable() {
        // CVE-2012-2459. Duplicating the unpaired node made these two sets produce an
        // identical root, so an event list could be padded without changing the anchor.
        String three = merkle.computeMerkleRoot(List.of(A, B, C));
        String fourWithDuplicate = merkle.computeMerkleRoot(List.of(A, B, C, C));

        assertThat(three).isNotEqualTo(fourWithDuplicate);
    }

    @Test
    @DisplayName("a leaf hash is not also a valid internal node hash")
    void leavesAndNodesAreDomainSeparated() {
        // Without domain separation an attacker can present an internal node as a leaf and
        // reproduce the same root from a different event set.
        String singleLeafRoot = merkle.computeMerkleRoot(List.of(A));

        assertThat(singleLeafRoot)
                .as("a single-leaf root must not be the bare leaf hash")
                .isNotEqualTo(A);
    }

    @Test
    @DisplayName("the root changes when any leaf changes")
    void rootIsSensitiveToEveryLeaf() {
        String base = merkle.computeMerkleRoot(List.of(A, B, C, D));

        assertThat(merkle.computeMerkleRoot(List.of(A, B, C, A))).isNotEqualTo(base);
        assertThat(merkle.computeMerkleRoot(List.of(D, B, C, A))).isNotEqualTo(base);
    }

    @Test
    @DisplayName("the root is stable for the same input")
    void rootIsDeterministic() {
        List<String> leaves = List.of(A, B, C, D, A);
        assertThat(merkle.computeMerkleRoot(leaves))
                .isEqualTo(merkle.computeMerkleRoot(leaves));
    }

    @Test
    @DisplayName("verification accepts the root it computed and rejects any other")
    void verificationRoundTrips() {
        List<String> leaves = List.of(A, B, C);
        String root = merkle.computeMerkleRoot(leaves);

        assertThat(merkle.verifyMerkleRoot(leaves, root)).isTrue();
        assertThat(merkle.verifyMerkleRoot(leaves, B)).isFalse();
        assertThat(merkle.verifyMerkleRoot(List.of(A, B, D), root)).isFalse();
    }

    @Test
    @DisplayName("roots anchored before domain separation still verify")
    void legacyRootsRemainVerifiable() {
        // Batches already anchored on chain carry the old construction. They must not start
        // reporting as tampering the moment the scheme changes.
        List<String> leaves = List.of(A, B, C);
        String legacy = legacyRoot(leaves);

        assertThat(merkle.verifyMerkleRoot(leaves, legacy)).isTrue();
    }

    @Test
    @DisplayName("an empty batch is rejected rather than producing a root")
    void emptyBatchIsRejected() {
        assertThatThrownBy(() -> merkle.computeMerkleRoot(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> merkle.computeMerkleRoot(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** Mirrors the pre-fix construction, to pin the legacy-compatibility path. */
    private String legacyRoot(List<String> leafHashes) {
        if (leafHashes.size() == 1) {
            return leafHashes.get(0);
        }
        List<String> level = new java.util.ArrayList<>(leafHashes);
        while (level.size() > 1) {
            List<String> next = new java.util.ArrayList<>();
            for (int i = 0; i < level.size(); i += 2) {
                String left = level.get(i);
                String right = (i + 1 < level.size()) ? level.get(i + 1) : left;
                next.add(hashService.computeChainedHash(left, right));
            }
            level = next;
        }
        return level.get(0);
    }
}
