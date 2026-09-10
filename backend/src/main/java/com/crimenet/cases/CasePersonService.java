package com.crimenet.cases;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Victims, witnesses, accused and informants attached to a case.
 *
 * <p>This is the one place where PostgreSQL row-level security does the work. The
 * {@code case_person} table carries a policy (V3, hardened in V4) restricting rows to
 * officers holding a live, unrevoked assignment to that case, and the table is set to
 * FORCE ROW LEVEL SECURITY so the policy applies even though the application connects as
 * the table's owner.
 *
 * <p><b>Reads deliberately do not repeat the case-assignment check in Java.</b> Listing
 * enforces only that the caller's role may read cases at all; which rows come back is
 * decided by the database. That is the point: an officer who is not assigned receives an
 * empty list because PostgreSQL refuses to hand the rows over, not because application
 * code filtered them. It also fails closed — if the RLS binding were ever missing,
 * {@code current_setting} yields NULL, matches no assignment, and returns nothing.
 *
 * <p>Writes do check assignment in Java first, so an unauthorised create returns a clean
 * 403 rather than surfacing a raw constraint violation from the policy's WITH CHECK.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CasePersonService {

    private final CasePersonRepository casePersonRepository;
    private final CaseRepository caseRepository;
    private final CaseAssignmentRepository caseAssignmentRepository;
    private final PolicyEvaluationService policyService;
    private final UserService userService;
    private final AuditService auditService;

    /**
     * Attach a person to a case.
     *
     * <p>Note the method-level {@code @Transactional}: RlsAspect's pointcut is
     * {@code @annotation(...Transactional)}, which matches annotated <em>methods</em> only.
     * A class-level annotation would leave {@code app.current_user_id} unbound and every
     * row invisible.
     */
    @Transactional
    public CasePerson addPerson(UUID caseId, AddPersonRequest request) {
        if (request.personName() == null || request.personName().isBlank()) {
            throw new IllegalArgumentException("personName is required");
        }
        if (request.roleType() == null || request.roleType().isBlank()) {
            throw new IllegalArgumentException(
                    "roleType is required: VICTIM, WITNESS, ACCUSED or INFORMANT");
        }

        caseRepository.findById(caseId)
                .orElseThrow(() -> new EntityNotFoundException("Case not found: " + caseId));

        // Adding a person edits the case record, so it needs CASE.UPDATE plus assignment.
        policyService.enforceCasePermission(caseId, "CASE", "UPDATE");

        AppUser currentUser = userService.getCurrentUser();

        CasePerson person = CasePerson.builder()
                .caseId(caseId)
                .personName(request.personName())
                .roleType(request.roleType())
                .idType(request.idType())
                // These three columns are named *_encrypted, but no encryption is
                // implemented yet — they hold plaintext. Row-level security is what
                // protects them today. See LEGAL_DISCLAIMERS.md.
                .idNumberEncrypted(request.idNumber())
                .contactEncrypted(request.contact())
                .addressEncrypted(request.address())
                .notes(request.notes())
                .createdBy(currentUser.getId())
                .build();

        person = casePersonRepository.save(person);

        auditService.record("CASE_PERSON_ADDED", currentUser.getId(), person.getId(), caseId,
                Map.of("roleType", person.getRoleType()));

        log.info("Person {} ({}) added to case {}", person.getId(), person.getRoleType(), caseId);
        return person;
    }

    /**
     * List the persons on a case that the database is willing to show this caller.
     *
     * <p>No assignment check here on purpose — see the class comment.
     */
    @Transactional(readOnly = true)
    public List<CasePerson> listPersons(UUID caseId) {
        policyService.enforcePermission("CASE", "READ");
        List<CasePerson> visible = casePersonRepository.findByCaseId(caseId);
        log.debug("RLS returned {} case_person row(s) on case {}", visible.size(), caseId);
        return visible;
    }

    /**
     * Report why the caller can or cannot see this case's persons.
     *
     * <p>Exists to make the mechanism legible: comparing two officers side by side shows
     * the assigned one receiving rows and the unassigned one receiving none, with the
     * enforcement point named.
     */
    @Transactional(readOnly = true)
    public RlsStatus describeAccess(UUID caseId) {
        policyService.enforcePermission("CASE", "READ");
        AppUser currentUser = userService.getCurrentUser();

        boolean assigned = caseAssignmentRepository
                .existsByCaseIdAndUserIdAndRevokedAtIsNull(caseId, currentUser.getId());
        int visibleRows = casePersonRepository.findByCaseId(caseId).size();

        return new RlsStatus(
                currentUser.getId(),
                currentUser.getDisplayName(),
                assigned,
                visibleRows,
                "postgresql-row-level-security",
                assigned
                        ? "Assigned to this case — the row-level security policy matches, so the database returns the rows."
                        : "Not assigned to this case — the policy matches no rows, so the database returns none. "
                          + "The application did not filter this result.");
    }

    public record AddPersonRequest(
            String personName,
            String roleType,
            String idType,
            String idNumber,
            String contact,
            String address,
            String notes
    ) {}

    public record RlsStatus(
            UUID userId,
            String displayName,
            boolean assignedToCase,
            int visibleRows,
            String enforcedBy,
            String explanation
    ) {}
}
