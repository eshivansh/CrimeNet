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

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
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
    private final com.crimenet.identity.AppUserRepository appUserRepository;
    private final com.crimenet.cases.CaseRepository caseRepository;

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

        // Compute hashes.
        //
        // The chain hash used to cover previousEventHash and the payload only, leaving
        // event_type, actor_id, resource_id, resource_type and case_id stored but
        // unauthenticated. A DBA who disabled the append-only trigger could repoint
        // actor_id on a BREAK_GLASS_GRANTED row onto a different officer and both the local
        // chain and the Merkle anchor still verified clean. Every identity column that
        // makes the event mean what it means is now inside the hash.
        String canonicalPayload = canonicalize(payload);
        String payloadHash = hashService.computeSha256(canonicalPayload);

        Instant createdAt = Instant.now();
        String canonicalEvent = canonicalizeEvent(
                eventType, actorId, resourceId, resourceType, caseId, createdAt, payloadHash);
        String eventHash = hashService.computeChainedHash(previousEventHash, canonicalEvent);

        AuditEvent event = AuditEvent.builder()
                .eventType(eventType)
                .actorId(actorId)
                .resourceId(resourceId)
                .resourceType(resourceType)
                .caseId(caseId)
                // org_id existed on the table and was never written, which is why the audit
                // endpoints could not be tenant-scoped.
                .orgId(resolveOrgId(actorId, caseId))
                .payload(payload)
                .payloadHash(payloadHash)
                .previousEventHash(previousEventHash)
                .eventHash(eventHash)
                .build();
        // createdAt is inside the hash, so the stored value must be the hashed value
        // rather than one Hibernate generates a moment later.
        event.setCreatedAt(createdAt);

        event = auditEventRepository.save(event);
        log.debug("Audit event recorded: {} by {} on {} (hash: {})",
                eventType, actorId, resourceId, eventHash);
        return event;
    }

    /**
     * The organization an event belongs to: the actor's, falling back to the case's.
     *
     * <p>Resolved through the repository rather than UserService to keep the audit writer
     * free of the service graph it is auditing.
     */
    private UUID resolveOrgId(UUID actorId, UUID caseId) {
        if (actorId != null) {
            UUID fromActor = appUserRepository.findById(actorId)
                    .map(com.crimenet.identity.AppUser::getOrgId)
                    .orElse(null);
            if (fromActor != null) {
                return fromActor;
            }
        }
        if (caseId != null) {
            return caseRepository.findById(caseId)
                    .map(com.crimenet.cases.CaseRecord::getOrgId)
                    .orElse(null);
        }
        return null;
    }

    private UUID callerOrgId() {
        var authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication instanceof org.springframework.security.oauth2.server.resource
                .authentication.JwtAuthenticationToken token) {
            return appUserRepository.findByKeycloakSubject(token.getToken().getSubject())
                    .map(com.crimenet.identity.AppUser::getOrgId)
                    .orElse(null);
        }
        return null;
    }

    /** Administrators additionally see events written before org_id was populated. */
    private boolean callerIsAdmin() {
        var authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        return authentication != null && authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
    }

    /**
     * Walk the audit chain and recompute every link.
     *
     * <p>The chain existed but nothing ever verified it: no code recomputed an event hash
     * from the stored columns, so a break in the chain was undetectable through any API.
     * This recomputes each event's hash from its own persisted fields and checks that it
     * links to its predecessor.
     *
     * @param limit how many of the most recent events to walk
     */
    @Transactional(readOnly = true)
    public ChainVerificationResult verifyChain(int limit) {
        List<AuditEvent> recent = auditEventRepository
                .findAllByOrderByCreatedAtDesc(org.springframework.data.domain.PageRequest.of(0, limit))
                .getContent();

        // Oldest first, so each event can be checked against the one before it.
        List<AuditEvent> ordered = new java.util.ArrayList<>(recent);
        java.util.Collections.reverse(ordered);

        List<String> problems = new java.util.ArrayList<>();
        String expectedPrevious = null;

        for (int i = 0; i < ordered.size(); i++) {
            AuditEvent event = ordered.get(i);

            String canonicalPayload = canonicalize(event.getPayload());
            String recomputedPayloadHash = hashService.computeSha256(canonicalPayload);
            if (!recomputedPayloadHash.equals(event.getPayloadHash())) {
                problems.add("Event " + event.getId() + ": payload does not match payload_hash");
            }

            String canonicalEvent = canonicalizeEvent(
                    event.getEventType(), event.getActorId(), event.getResourceId(),
                    event.getResourceType(), event.getCaseId(), event.getCreatedAt(),
                    event.getPayloadHash());
            String recomputedEventHash =
                    hashService.computeChainedHash(event.getPreviousEventHash(), canonicalEvent);

            if (!recomputedEventHash.equals(event.getEventHash())) {
                // Events written before the chain covered the identity columns hash the
                // payload alone; recognise those rather than reporting them as tampering.
                String legacyHash =
                        hashService.computeChainedHash(event.getPreviousEventHash(), canonicalPayload);
                if (legacyHash.equals(event.getEventHash())) {
                    problems.add("Event " + event.getId() + ": legacy v1 chain hash "
                            + "(covers the payload only, not the actor or resource)");
                } else {
                    problems.add("Event " + event.getId() + ": event_hash does not match its own fields");
                }
            }

            if (i > 0 && !java.util.Objects.equals(expectedPrevious, event.getPreviousEventHash())) {
                problems.add("Event " + event.getId() + ": chain break — previous_event_hash does not "
                        + "match the preceding event");
            }
            expectedPrevious = event.getEventHash();
        }

        boolean intact = problems.isEmpty();
        if (!intact) {
            log.error("AUDIT_CHAIN_VERIFICATION_FAILED: {} problem(s) across {} events",
                    problems.size(), ordered.size());
        }
        return new ChainVerificationResult(ordered.size(), intact, problems);
    }

    public record ChainVerificationResult(int eventsChecked, boolean intact, List<String> problems) {}

    /**
     * List audit events (AUDITOR role only — enforced at controller level).
     */
    @Transactional(readOnly = true)
    public Page<AuditEvent> listEvents(Pageable pageable) {
        return auditEventRepository.findForOrg(callerOrgId(), callerIsAdmin(), pageable);
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> listEventsByCase(UUID caseId, Pageable pageable) {
        return auditEventRepository.findForOrgByCase(caseId, callerOrgId(), callerIsAdmin(), pageable);
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> listEventsByType(String eventType, Pageable pageable) {
        return auditEventRepository.findForOrgByType(eventType, callerOrgId(), callerIsAdmin(), pageable);
    }

    /**
     * Field-tagged canonical form of the whole event.
     *
     * <p>Tagged and length-delimited rather than concatenated: {@code computeChainedHash}
     * joins its inputs with no separator, so without delimiters two different field
     * splits could produce the same string and therefore the same hash.
     */
    String canonicalizeEvent(String eventType, UUID actorId, UUID resourceId, String resourceType,
                             UUID caseId, Instant createdAt, String payloadHash) {
        return new StringBuilder()
                .append("v2|")
                .append("type=").append(nullSafe(eventType)).append('|')
                .append("actor=").append(nullSafe(actorId)).append('|')
                .append("resource=").append(nullSafe(resourceId)).append('|')
                .append("resourceType=").append(nullSafe(resourceType)).append('|')
                .append("case=").append(nullSafe(caseId)).append('|')
                .append("at=").append(createdAt == null ? "" : createdAt.toString()).append('|')
                .append("payloadHash=").append(nullSafe(payloadHash))
                .toString();
    }

    private String nullSafe(Object value) {
        return value == null ? "" : value.toString();
    }

    private String canonicalize(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(new TreeMap<>(payload));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to canonicalize audit payload", e);
        }
    }
}
