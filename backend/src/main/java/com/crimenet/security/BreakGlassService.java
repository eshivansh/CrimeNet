package com.crimenet.security;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Break-Glass Service — emergency access for critical situations (§11).
 *
 * Flow: reason required → step-up MFA (validated at controller) → risk evaluation →
 *       time-boxed, restricted (view-only, watermarked) grant → automatic expiry →
 *       mandatory supervisor notification + BREAK_GLASS audit events.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BreakGlassService {

    private final BreakGlassRepository breakGlassRepository;
    private final UserService userService;
    private final AuditService auditService;
    private final com.crimenet.cases.CaseRepository caseRepository;
    private final StepUpVerificationService stepUpVerificationService;
    private final SecurityEventService securityEventService;

    private static final int DEFAULT_DURATION_MINUTES = 30;
    private static final int MAX_BREAK_GLASS_PER_24H = 3;

    @Transactional
    public BreakGlassGrant requestBreakGlass(UUID caseId, String reason) {
        AppUser currentUser = userService.getCurrentUser();

        if (caseId == null) {
            throw new IllegalArgumentException("caseId is required");
        }
        if (reason == null || reason.trim().length() < 10) {
            throw new IllegalArgumentException("A detailed justification reason (min 10 chars) is required for emergency break-glass");
        }

        // Step-up is proven by the identity provider in the signed token, never by a
        // value the caller supplies. The previous check was a regex on a request field.
        stepUpVerificationService.requireStepUp("emergency break-glass access");

        // Prevent duplicate active break-glass grants for the same case
        if (hasActiveGrant(currentUser.getId(), caseId)) {
            throw new IllegalStateException("An active emergency break-glass grant already exists for this case.");
        }

        // Enforce rate limiting: maximum 3 emergency grants per officer per 24 hours
        Instant twentyFourHoursAgo = Instant.now().minus(24, java.time.temporal.ChronoUnit.HOURS);
        long recentGrants = breakGlassRepository.countByGrantedToAndCreatedAtAfter(currentUser.getId(), twentyFourHoursAgo);
        if (recentGrants >= MAX_BREAK_GLASS_PER_24H) {
            securityEventService.record("BREAK_GLASS_QUOTA_EXCEEDED", "HIGH", currentUser.getId(), caseId, null,
                    "Officer exceeded the 24-hour emergency-access quota (" + recentGrants + " grants in window)");
            throw new org.springframework.security.access.AccessDeniedException(
                    "Break-glass emergency quota exceeded: Maximum " + MAX_BREAK_GLASS_PER_24H +
                    " emergency grants permitted per 24-hour window. Please contact your Department Supervisor or Legal Registrar.");
        }

        // Validate case existence and tenant boundary
        com.crimenet.cases.CaseRecord caseRecord = caseRepository.findById(caseId)
                .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Case not found: " + caseId));

        if (!currentUser.getOrgId().equals(caseRecord.getOrgId())) {
            securityEventService.denied("BREAK_GLASS_CROSS_TENANT", currentUser.getId(), caseId,
                    "Attempted emergency access to a case owned by organization " + caseRecord.getOrgId());
            throw new org.springframework.security.access.AccessDeniedException(
                    "Cross-tenant break-glass forbidden. Cannot access cases belonging to another agency/organization.");
        }

        // Record the request audit event FIRST (even if it will be denied). stepUpVerified
        // reflects the verified token claim, not the caller's assertion about itself.
        auditService.record("BREAK_GLASS_REQUESTED", currentUser.getId(), null, caseId,
                Map.of("reason", reason, "stepUpVerified", stepUpVerificationService.hasStepUp()));

        // Create time-boxed grant
        Instant expiresAt = Instant.now().plusSeconds(DEFAULT_DURATION_MINUTES * 60L);

        BreakGlassGrant grant = BreakGlassGrant.builder()
                .caseId(caseId)
                .grantedTo(currentUser.getId())
                .reason(reason)
                .expiresAt(expiresAt)
                .status("ACTIVE")
                .build();

        grant = breakGlassRepository.save(grant);

        // Audit the grant
        auditService.record("BREAK_GLASS_GRANTED", currentUser.getId(), grant.getId(), caseId,
                Map.of("reason", reason, "expiresAt", expiresAt.toString(),
                        "durationMinutes", DEFAULT_DURATION_MINUTES));

        // Mandatory supervisor notification (§11)
        notifySupervisor(currentUser, caseId, reason, grant.getId(), expiresAt);

        log.warn("BREAK_GLASS_GRANTED: User {} granted emergency access to case {} for {} minutes. Reason: {}",
                currentUser.getId(), caseId, DEFAULT_DURATION_MINUTES, reason);

        return grant;
    }

    /**
     * Check if a user has an active break-glass grant for a case.
     */
    @Transactional(readOnly = true)
    public boolean hasActiveGrant(UUID userId, UUID caseId) {
        return breakGlassRepository.existsByGrantedToAndCaseIdAndStatusAndExpiresAtAfter(
                userId, caseId, "ACTIVE", Instant.now());
    }

    /**
     * Revoke a break-glass grant early.
     */
    @Transactional
    public BreakGlassGrant revokeGrant(UUID grantId) {
        BreakGlassGrant grant = breakGlassRepository.findById(grantId)
                .orElseThrow(() -> new IllegalArgumentException("Grant not found"));

        AppUser currentUser = userService.getCurrentUser();

        // Revocation used to be open to any authenticated caller who knew a grant id,
        // which let an unrelated user cancel a legitimate emergency mid-incident and
        // left a false BREAK_GLASS_REVOKED entry attributed to them.
        boolean isGrantee = currentUser.getId().equals(grant.getGrantedTo());
        boolean isSupervisor = hasAnyRole("SUPERVISOR", "ADMIN");
        if (!isGrantee && !isSupervisor) {
            securityEventService.denied("BREAK_GLASS_REVOKE_FORBIDDEN", currentUser.getId(), grant.getCaseId(),
                    "Attempted to revoke break-glass grant " + grantId + " belonging to " + grant.getGrantedTo());
            throw new org.springframework.security.access.AccessDeniedException(
                    "Only the grantee or a supervisor may revoke an emergency access grant.");
        }

        com.crimenet.cases.CaseRecord caseRecord = caseRepository.findById(grant.getCaseId()).orElse(null);
        if (caseRecord != null && !currentUser.getOrgId().equals(caseRecord.getOrgId())) {
            securityEventService.denied("BREAK_GLASS_REVOKE_CROSS_TENANT", currentUser.getId(), grant.getCaseId(),
                    "Attempted cross-tenant revocation of grant " + grantId);
            throw new org.springframework.security.access.AccessDeniedException(
                    "Cross-tenant break-glass revocation is forbidden.");
        }

        if (!"ACTIVE".equals(grant.getStatus())) {
            throw new IllegalStateException(
                    "Grant " + grantId + " is already " + grant.getStatus() + " and cannot be revoked.");
        }

        grant.setStatus("REVOKED");
        grant.setRevokedAt(Instant.now());
        grant = breakGlassRepository.save(grant);

        auditService.record("BREAK_GLASS_REVOKED", currentUser.getId(), grantId, grant.getCaseId(),
                Map.of("revokedBy", currentUser.getId().toString()));

        log.info("Break-glass grant {} revoked by {}", grantId, currentUser.getId());
        return grant;
    }

    /**
     * Scheduled job: auto-expire break-glass grants past their expiry time.
     */
    @Scheduled(fixedDelayString = "${crimenet.break-glass.expiry-check-ms:60000}")
    @Transactional
    public void expireGrants() {
        List<BreakGlassGrant> expired = breakGlassRepository
                .findByStatusAndExpiresAtBefore("ACTIVE", Instant.now());

        for (BreakGlassGrant grant : expired) {
            grant.setStatus("EXPIRED");
            breakGlassRepository.save(grant);
            auditService.record("BREAK_GLASS_EXPIRED", grant.getGrantedTo(), grant.getId(),
                    grant.getCaseId(), Map.of("expiredAt", Instant.now().toString()));
            log.info("Break-glass grant {} auto-expired for case {}", grant.getId(), grant.getCaseId());
        }
    }

    private boolean hasAnyRole(String... roles) {
        var authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        List<String> wanted = java.util.Arrays.stream(roles).map(r -> "ROLE_" + r).toList();
        return authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .anyMatch(wanted::contains);
    }

    /**
     * Mandatory supervisor notification for break-glass grants (§11).
     * In prototype: creates a SUPERVISOR_NOTIFICATION audit event and logs at WARN level.
     * In production: would dispatch via email/SMS/push to the user's direct supervisor.
     */
    private void notifySupervisor(AppUser grantee, UUID caseId, String reason, UUID grantId, Instant expiresAt) {
        // Record the notification as an audit event for traceability
        auditService.record("SUPERVISOR_NOTIFIED_BREAK_GLASS", grantee.getId(), grantId, caseId,
                Map.of(
                        "granteeId", grantee.getId().toString(),
                        "granteeName", grantee.getDisplayName(),
                        "reason", reason,
                        "expiresAt", expiresAt.toString(),
                        "notificationType", "BREAK_GLASS_ALERT"
                ));

        log.warn("SUPERVISOR_NOTIFICATION: Break-glass grant {} issued to {} for case {}. Supervisor must review.",
                grantId, grantee.getDisplayName(), caseId);
    }
}
