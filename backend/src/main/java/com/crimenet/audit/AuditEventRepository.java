package com.crimenet.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {

    Page<AuditEvent> findByCaseIdOrderByCreatedAtDesc(UUID caseId, Pageable pageable);

    Page<AuditEvent> findByEventTypeOrderByCreatedAtDesc(String eventType, Pageable pageable);

    Page<AuditEvent> findByActorIdOrderByCreatedAtDesc(UUID actorId, Pageable pageable);

    Page<AuditEvent> findByCaseIdAndCreatedAtBetweenOrderByCreatedAtDesc(
            UUID caseId, Instant from, Instant to, Pageable pageable);

    @Query(value = "SELECT pg_advisory_xact_lock(hashtext('audit_event_chain'))", nativeQuery = true)
    void acquireChainLock();

    @Query("SELECT ae FROM AuditEvent ae ORDER BY ae.createdAt DESC LIMIT 1")
    Optional<AuditEvent> findLatest();

    Page<AuditEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);

    /**
     * Org-scoped listing.
     *
     * <p>The audit endpoints returned every event in the system to any AUDITOR or ADMIN,
     * and those roles are global rather than per-organization — so an auditor at one agency
     * could read another agency's case numbers, evidence codes, content hashes, object keys,
     * break-glass justifications and AI query text. Filtering happens in the query rather
     * than after the fact so it cannot be paged around.
     *
     * <p>{@code includeLegacy} covers rows written before org_id was populated; only
     * administrators see those.
     */
    @Query("""
           SELECT ae FROM AuditEvent ae
           WHERE ae.orgId = :orgId OR (:includeLegacy = true AND ae.orgId IS NULL)
           ORDER BY ae.createdAt DESC
           """)
    Page<AuditEvent> findForOrg(UUID orgId, boolean includeLegacy, Pageable pageable);

    @Query("""
           SELECT ae FROM AuditEvent ae
           WHERE ae.caseId = :caseId
             AND (ae.orgId = :orgId OR (:includeLegacy = true AND ae.orgId IS NULL))
           ORDER BY ae.createdAt DESC
           """)
    Page<AuditEvent> findForOrgByCase(UUID caseId, UUID orgId, boolean includeLegacy, Pageable pageable);

    @Query("""
           SELECT ae FROM AuditEvent ae
           WHERE ae.eventType = :eventType
             AND (ae.orgId = :orgId OR (:includeLegacy = true AND ae.orgId IS NULL))
           ORDER BY ae.createdAt DESC
           """)
    Page<AuditEvent> findForOrgByType(String eventType, UUID orgId, boolean includeLegacy, Pageable pageable);

    @Query("SELECT ae FROM AuditEvent ae WHERE ae.createdAt >= :from AND ae.createdAt <= :to ORDER BY ae.createdAt ASC")
    List<AuditEvent> findBetweenInstants(Instant from, Instant to);

    List<AuditEvent> findByCreatedAtAfterOrderByCreatedAtAsc(Instant since, Pageable pageable);

    long countByCreatedAtAfter(Instant since);

    /**
     * Events strictly after the (createdAt, id) tuple of the last anchored event.
     *
     * <p>createdAt comes from {@code @CreationTimestamp} in the JVM, not the database, so
     * ties are possible. A plain {@code createdAt > :since} therefore skipped any event
     * sharing the watermark timestamp — permanently, since the watermark then moved past
     * it. Ordering and filtering on the (timestamp, id) pair gives a total order.
     */
    @Query("""
           SELECT ae FROM AuditEvent ae
           WHERE ae.createdAt > :since
              OR (ae.createdAt = :since AND ae.id > :sinceId)
           ORDER BY ae.createdAt ASC, ae.id ASC
           """)
    List<AuditEvent> findAfterTuple(Instant since, UUID sinceId, Pageable pageable);

    /**
     * Re-reads exactly the events a batch covered, by the same total order used to build it.
     *
     * <p>Verification previously re-derived membership from an inclusive timestamp range,
     * which could pull in events inserted later that shared the boundary timestamp and
     * report a spurious AUDIT_TAMPERING_DETECTED.
     */
    @Query("""
           SELECT ae FROM AuditEvent ae
           WHERE (ae.createdAt > :fromTime OR (ae.createdAt = :fromTime AND ae.id >= :fromId))
             AND (ae.createdAt < :toTime   OR (ae.createdAt = :toTime   AND ae.id <= :toId))
           ORDER BY ae.createdAt ASC, ae.id ASC
           """)
    List<AuditEvent> findInTupleRange(Instant fromTime, UUID fromId, Instant toTime, UUID toId);

    @Query("SELECT ae FROM AuditEvent ae ORDER BY ae.createdAt ASC, ae.id ASC LIMIT 1")
    Optional<AuditEvent> findEarliest();
}
