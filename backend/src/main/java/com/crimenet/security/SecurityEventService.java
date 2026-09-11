package com.crimenet.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.UUID;

/**
 * Writes the security-event trail.
 *
 * <p>{@link SecurityEvent} and its repository already existed but were never injected
 * anywhere — every denied access, cross-tenant attempt and quota breach was a
 * {@code log.warn} and nothing more, so there was no alertable record and nothing to
 * correlate. This is the missing writer.
 *
 * <p>Recorded in its own transaction: a denial is a fact about an attempt, and it must
 * survive the rollback of the request that was refused.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String eventType, String severity, UUID actorId, UUID caseId,
                       UUID resourceId, String description) {
        try {
            SecurityEvent event = SecurityEvent.builder()
                    .eventType(eventType)
                    .severity(severity)
                    .actorId(actorId)
                    .caseId(caseId)
                    .resourceId(resourceId)
                    .description(truncate(description))
                    .ipAddress(clientIp())
                    .resolved(false)
                    .build();
            securityEventRepository.save(event);
            log.warn("SECURITY_EVENT [{}] {} — {}", severity, eventType, description);
        } catch (RuntimeException e) {
            // Never let the security trail turn a denial into a 500; the denial still stands.
            log.error("Failed to persist security event {} — {}", eventType, e.getMessage());
        }
    }

    public void denied(String eventType, UUID actorId, UUID caseId, String description) {
        record(eventType, "HIGH", actorId, caseId, null, description);
    }

    private String truncate(String description) {
        if (description == null) {
            return "(no description)";
        }
        return description.length() <= 2000 ? description : description.substring(0, 1997) + "...";
    }

    private String clientIp() {
        try {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
                String forwarded = attrs.getRequest().getHeader("X-Forwarded-For");
                if (forwarded != null && !forwarded.isBlank()) {
                    return forwarded.split(",")[0].trim();
                }
                return attrs.getRequest().getRemoteAddr();
            }
        } catch (RuntimeException ignored) {
            // Scheduled jobs have no request context.
        }
        return null;
    }
}
