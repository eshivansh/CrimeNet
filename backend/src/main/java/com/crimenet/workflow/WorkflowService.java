package com.crimenet.workflow;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.retention.LegalHoldRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Workflow service — governs document/case lifecycle transitions (§12).
 *
 * Lifecycle: ACTIVE → SEALED → ARCHIVED → RETENTION_REVIEW → DISPOSITION
 * Legal holds block DISPOSITION entirely at both service and Object Lock layers.
 * Deletion/disposition is never a direct DELETE — it's an approval-based workflow.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WorkflowService {

    private final WorkflowTransitionRepository transitionRepository;
    private final LegalHoldRepository legalHoldRepository;
    private final UserService userService;
    private final AuditService auditService;

    private static final Map<String, Set<String>> VALID_TRANSITIONS = Map.of(
            "ACTIVE", Set.of("SEALED"),
            "SEALED", Set.of("ARCHIVED"),
            "ARCHIVED", Set.of("RETENTION_REVIEW"),
            "RETENTION_REVIEW", Set.of("DISPOSITION")
    );

    @Transactional
    public WorkflowTransition transition(String resourceType, UUID resourceId, UUID caseId,
                                         String fromStatus, String toStatus, String reason) {
        AppUser currentUser = userService.getCurrentUser();

        // Validate transition is legal
        Set<String> allowed = VALID_TRANSITIONS.getOrDefault(fromStatus, Set.of());
        if (!allowed.contains(toStatus)) {
            throw new IllegalStateException(
                    String.format("Invalid transition: %s → %s for %s", fromStatus, toStatus, resourceType));
        }

        // Block DISPOSITION if legal hold exists
        if ("DISPOSITION".equals(toStatus)) {
            boolean hasHold = !legalHoldRepository.findByCaseIdAndReleasedAtIsNull(caseId).isEmpty();
            if (hasHold) {
                auditService.record("DISPOSITION_BLOCKED_BY_LEGAL_HOLD", currentUser.getId(),
                        resourceId, caseId, Map.of("reason", reason));
                throw new IllegalStateException("Cannot dispose: active legal hold exists on case " + caseId);
            }
        }

        WorkflowTransition wt = WorkflowTransition.builder()
                .resourceType(resourceType)
                .resourceId(resourceId)
                .caseId(caseId)
                .fromStatus(fromStatus)
                .toStatus(toStatus)
                .transitionedBy(currentUser.getId())
                .transitionedAt(Instant.now())
                .reason(reason)
                .approvalRequired("DISPOSITION".equals(toStatus))
                .build();

        wt = transitionRepository.save(wt);

        auditService.record("WORKFLOW_TRANSITION", currentUser.getId(), resourceId, caseId,
                Map.of("resourceType", resourceType, "from", fromStatus, "to", toStatus, "reason", reason));

        log.info("Workflow transition: {} {} from {} to {}", resourceType, resourceId, fromStatus, toStatus);
        return wt;
    }

    @Transactional(readOnly = true)
    public List<WorkflowTransition> getHistory(UUID resourceId) {
        return transitionRepository.findByResourceIdOrderByTransitionedAtDesc(resourceId);
    }
}
