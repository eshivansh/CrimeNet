package com.crimenet.audit;

import com.crimenet.documents.HashService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Audit service — records append-only, hash-chained audit events.
 * Every state mutation in the system MUST call this service.
 *
 * The hash chain: event_hash = SHA-256(canonical_json(payload) + previous_event_hash)
 * This provides internal self-consistency verification.
 * External Merkle anchoring (Phase 7) provides tamper-evidence against privileged insiders.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditEventRepository auditEventRepository;
    private final HashService hashService;
    private final ObjectMapper objectMapper;

    /**
     * Record an audit event with hash chaining.
     * Uses REQUIRES_NEW propagation so audit always commits even if the outer transaction rolls back.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditEvent record(String eventType, UUID actorId, UUID resourceId, UUID caseId,
                             Map<String, Object> additionalPayload) {
        return record(eventType, actorId, resourceId, caseId, null, additionalPayload);
    }

    /**
     * Convenience overload with resource type tracking.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditEvent record(String eventType, UUID actorId, UUID resourceId, UUID caseId,
                             String resourceType, Map<String, Object> additionalPayload) {
        try {
            auditEventRepository.acquireChainLock();
        } catch (Exception e) {
            log.warn("AUDIT_CHAIN_LOCK_BUSY: Initial advisory lock attempt failed ({}), retrying...", e.getMessage());
            try {
                Thread.sleep(50);
                auditEventRepository.acquireChainLock();
            } catch (Exception retryEx) {
                log.error("AUDIT_CHAIN_LOCK_FAILED: Critical: Unable to acquire audit chain serialization lock. Failing closed to prevent fork.", retryEx);
                throw new IllegalStateException("Audit chain serialization lock failed: concurrent audit write contention", retryEx);
            }
        }

        // Prepare payload with correlation ID
        Map<String, Object> payload = new HashMap<>(additionalPayload != null ? additionalPayload : Map.of());
        String correlationId = org.slf4j.MDC.get(com.crimenet.infrastructure.CorrelationIdFilter.CORRELATION_ID_MDC_KEY);
        if (correlationId != null) {
            payload.put("correlationId", correlationId);
        }

        // Get previous event hash for chain
        String previousEventHash = auditEventRepository.findLatest()
                .map(AuditEvent::getEventHash)
                .orElse(null);

        // Compute hashes
        String canonicalPayload = canonicalize(payload);
        String payloadHash = hashService.computeSha256(canonicalPayload);
        String eventHash = hashService.computeChainedHash(previousEventHash, canonicalPayload);

        AuditEvent event = AuditEvent.builder()
                .eventType(eventType)
                .actorId(actorId)
                .resourceId(resourceId)
                .resourceType(resourceType)
                .caseId(caseId)
                .payload(payload)
                .payloadHash(payloadHash)
                .previousEventHash(previousEventHash)
                .eventHash(eventHash)
                .build();

        event = auditEventRepository.save(event);
        log.debug("Audit event recorded: {} by {} on {} (hash: {})",
                eventType, actorId, resourceId, eventHash);
        return event;
    }

    /**
     * List audit events (AUDITOR role only — enforced at controller level).
     */
    @Transactional(readOnly = true)
    public Page<AuditEvent> listEvents(Pageable pageable) {
        return auditEventRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> listEventsByCase(UUID caseId, Pageable pageable) {
        return auditEventRepository.findByCaseIdOrderByCreatedAtDesc(caseId, pageable);
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> listEventsByType(String eventType, Pageable pageable) {
        return auditEventRepository.findByEventTypeOrderByCreatedAtDesc(eventType, pageable);
    }

    private String canonicalize(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(new TreeMap<>(payload));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to canonicalize audit payload", e);
        }
    }
}
