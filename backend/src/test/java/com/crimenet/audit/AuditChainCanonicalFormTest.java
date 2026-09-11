package com.crimenet.audit;

import com.crimenet.documents.HashService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The audit chain hash used to cover the payload alone, so actor, event type, resource and
 * case could be rewritten without detection.
 */
class AuditChainCanonicalFormTest {

    private final AuditService audit = new AuditService(null, new HashService(), null, null, null);

    private final UUID actor = UUID.randomUUID();
    private final UUID resource = UUID.randomUUID();
    private final UUID caseId = UUID.randomUUID();
    private final Instant at = Instant.parse("2026-09-11T10:00:00.123456Z");

    private String form(String type, UUID actorId, UUID resourceId, UUID caseRef) {
        return audit.canonicalizeEvent(type, actorId, resourceId, "EVIDENCE", caseRef, at, "ab".repeat(32));
    }

    @Test
    @DisplayName("repointing the actor changes the canonical form")
    void actorIsCovered() {
        // The attack this closes: repoint actor_id on a BREAK_GLASS_GRANTED row onto a
        // different officer, with both the chain and the Merkle anchor still verifying.
        assertThat(form("BREAK_GLASS_GRANTED", actor, resource, caseId))
                .isNotEqualTo(form("BREAK_GLASS_GRANTED", UUID.randomUUID(), resource, caseId));
    }

    @Test
    @DisplayName("event type, resource and case are all covered")
    void identityColumnsAreCovered() {
        String base = form("CUSTODY_TRANSFERRED", actor, resource, caseId);
        assertThat(form("DOCUMENT_DOWNLOADED", actor, resource, caseId)).isNotEqualTo(base);
        assertThat(form("CUSTODY_TRANSFERRED", actor, UUID.randomUUID(), caseId)).isNotEqualTo(base);
        assertThat(form("CUSTODY_TRANSFERRED", actor, resource, UUID.randomUUID())).isNotEqualTo(base);
    }

    @Test
    @DisplayName("the timestamp is canonicalised at the precision PostgreSQL stores")
    void timestampUsesStoredPrecision() {
        // Regression: sub-microsecond digits were hashed and then dropped by TIMESTAMPTZ,
        // so every event failed its own verification after the round trip.
        String inMemory = audit.canonicalizeEvent("X", actor, resource, "R", caseId,
                Instant.parse("2026-09-11T10:00:00.123456789Z"), "p");
        String asStored = audit.canonicalizeEvent("X", actor, resource, "R", caseId,
                Instant.parse("2026-09-11T10:00:00.123456Z"), "p");
        assertThat(inMemory).isEqualTo(asStored);
    }
}
