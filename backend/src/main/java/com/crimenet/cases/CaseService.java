package com.crimenet.cases;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.Year;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CaseService {

    private final CaseRepository caseRepository;
    private final CaseAssignmentRepository caseAssignmentRepository;
    private final UserService userService;
    private final PolicyEvaluationService policyService;
    private final AuditService auditService;

    /**
     * Create a new case and auto-assign the creator.
     */
    @Transactional
    public CaseRecord createCase(CreateCaseRequest request) {
        policyService.enforcePermission("CASE", "CREATE");

        AppUser currentUser = userService.getCurrentUser();
        String caseNumber = generateCaseNumber(currentUser.getOrgId());

        CaseRecord caseRecord = CaseRecord.builder()
                .orgId(currentUser.getOrgId())
                .caseNumber(caseNumber)
                .title(request.title())
                .description(request.description())
                .firId(request.firId())
                .classification(request.classification() != null ? request.classification() : "STANDARD")
                .createdBy(currentUser.getId())
                .build();

        caseRecord = caseRepository.save(caseRecord);

        // Auto-assign creator as LEAD_INVESTIGATOR
        CaseAssignment assignment = CaseAssignment.builder()
                .caseId(caseRecord.getId())
                .userId(currentUser.getId())
                .roleInCase("LEAD_INVESTIGATOR")
                .assignedBy(currentUser.getId())
                .build();
        caseAssignmentRepository.save(assignment);

        auditService.record("CASE_CREATED", currentUser.getId(), caseRecord.getId(), caseRecord.getId(),
                Map.of("caseNumber", caseNumber, "classification", caseRecord.getClassification()));

        log.info("Case created: {} by user {}", caseNumber, currentUser.getId());
        return caseRecord;
    }

    /**
     * Get a case by ID — enforces case assignment access.
     */
    public CaseRecord getCase(UUID caseId) {
        CaseRecord caseRecord = caseRepository.findById(caseId)
                .orElseThrow(() -> new EntityNotFoundException("Case not found: " + caseId));
        policyService.enforceCaseAccess(caseId);
        return caseRecord;
    }

    /**
     * List cases the current user is assigned to.
     */
    public Page<CaseRecord> listMyCases(Pageable pageable) {
        AppUser currentUser = userService.getCurrentUser();

        if (policyService.hasRole("ADMIN")) {
            return caseRepository.findByOrgId(currentUser.getOrgId(), pageable);
        }

        List<UUID> assignedCaseIds = caseAssignmentRepository.findActiveCaseIdsByUserId(currentUser.getId());
        if (assignedCaseIds.isEmpty()) {
            return Page.empty(pageable);
        }
        return caseRepository.findAllById(assignedCaseIds).stream()
                .collect(java.util.stream.Collectors.collectingAndThen(
                        java.util.stream.Collectors.toList(),
                        list -> new org.springframework.data.domain.PageImpl<>(list, pageable, list.size())
                ));
    }

    /**
     * Assign a user to a case.
     */
    @Transactional
    public CaseAssignment assignUser(UUID caseId, UUID userId, String roleInCase) {
        policyService.enforceCasePermission(caseId, "CASE", "ASSIGN");

        // Verify case and user exist
        CaseRecord caseRecord = getCase(caseId);
        AppUser assignee = userService.getUser(userId);

        // Cross-tenant boundary enforcement
        if (!assignee.getOrgId().equals(caseRecord.getOrgId()) && !policyService.hasRole("ADMIN")) {
            throw new SecurityException("Cross-tenant assignment denied: Officer belongs to a different organization");
        }

        // Duplicate active assignment prevention
        if (caseAssignmentRepository.existsByCaseIdAndUserIdAndRevokedAtIsNull(caseId, userId)) {
            throw new IllegalStateException("User is already actively assigned to this case");
        }

        AppUser currentUser = userService.getCurrentUser();

        CaseAssignment assignment = CaseAssignment.builder()
                .caseId(caseId)
                .userId(userId)
                .roleInCase(roleInCase)
                .assignedBy(currentUser.getId())
                .build();

        assignment = caseAssignmentRepository.save(assignment);

        auditService.record("CASE_USER_ASSIGNED", currentUser.getId(), caseId, caseId,
                Map.of("assignedUserId", userId.toString(), "roleInCase", roleInCase));

        log.info("User {} assigned to case {} as {}", userId, caseId, roleInCase);
        return assignment;
    }

    /**
     * Update case status (e.g., ACTIVE → SEALED → ARCHIVED).
     */
    @Transactional
    public CaseRecord updateStatus(UUID caseId, String newStatus) {
        policyService.enforceCasePermission(caseId, "CASE", "UPDATE");

        CaseRecord caseRecord = getCase(caseId);
        String oldStatus = caseRecord.getStatus();
        caseRecord.setStatus(newStatus);
        caseRecord.setUpdatedAt(Instant.now());

        AppUser currentUser = userService.getCurrentUser();
        auditService.record("CASE_STATUS_CHANGED", currentUser.getId(), caseId, caseId,
                Map.of("oldStatus", oldStatus, "newStatus", newStatus));

        log.info("Case {} status changed: {} → {}", caseId, oldStatus, newStatus);
        return caseRepository.save(caseRecord);
    }

    /**
     * Get all assignments for a case.
     */
    public List<CaseAssignment> getCaseAssignments(UUID caseId) {
        policyService.enforceCaseAccess(caseId);
        return caseAssignmentRepository.findByCaseIdAndRevokedAtIsNull(caseId);
    }

    private String generateCaseNumber(UUID orgId) {
        long count = caseRepository.count() + 1;
        return String.format("CASE-%s-UP-%06d", Year.now().getValue(), count);
    }
}
