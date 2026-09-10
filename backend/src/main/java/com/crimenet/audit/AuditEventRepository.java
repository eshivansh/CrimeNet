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

    @Query("SELECT ae FROM AuditEvent ae WHERE ae.createdAt >= :from AND ae.createdAt <= :to ORDER BY ae.createdAt ASC")
    List<AuditEvent> findBetweenInstants(Instant from, Instant to);

    List<AuditEvent> findByCreatedAtAfterOrderByCreatedAtAsc(Instant since, Pageable pageable);

    long countByCreatedAtAfter(Instant since);
}
