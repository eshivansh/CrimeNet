package com.crimenet.policy;

import com.crimenet.cases.CaseAssignmentRepository;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Central ABAC+RBAC policy evaluation engine.
 *
 * All fine-grained authorization decisions are made here — never solely from JWT claims.
 * This service checks:
 *   1. JWT roles (coarse RBAC)
 *   2. Live DB case assignment (is the user assigned to this case?)
 *   3. Resource classification (does the user's clearance allow access?)
 *   4. DB-stored permissions (does the user's role grant the action on the resource?)
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class PolicyEvaluationService {

    private final UserService userService;
    private final CaseAssignmentRepository caseAssignmentRepository;
    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final com.crimenet.security.BreakGlassService breakGlassService;

    /**
     * Build a full security context for the current request.
     */
    public SecurityContext buildContext() {
        AppUser user = userService.getCurrentUser();
        List<String> roles = getCurrentRoles();
        List<UUID> assignedCases = caseAssignmentRepository.findActiveCaseIdsByUserId(user.getId());

        return SecurityContext.builder()
                .userId(user.getId())
                .orgId(user.getOrgId())
                .keycloakSubject(user.getKeycloakSubject())
                .displayName(user.getDisplayName())
                .departmentId(user.getDepartmentId())
                .roles(roles)
                .assignedCaseIds(assignedCases)
                .build();
    }

    /**
     * Check if the current user has a specific role.
     */
    public boolean hasRole(String role) {
        return getCurrentRoles().contains(role);
    }

    /**
     * Check if the current user is assigned to a specific case.
     */
    public boolean isAssignedToCase(UUID caseId) {
        AppUser user = userService.getCurrentUser();
        return caseAssignmentRepository.existsByCaseIdAndUserIdAndRevokedAtIsNull(caseId, user.getId());
    }

    /**
     * Check if the current user has a specific permission (resource + action).
     */
    public boolean hasPermission(String resource, String action) {
        List<String> roles = getCurrentRoles();
        List<UUID> roleIds = roles.stream()
                .map(r -> roleRepository.findByName(r).map(Role::getId).orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();

        if (roleIds.isEmpty()) return false;

        return !permissionRepository
                .findByRoleIdInAndResourceAndAction(roleIds, resource, action)
                .isEmpty();
    }

    private final com.crimenet.cases.CaseRepository caseRepository;

    /**
     * Enforce that the current user is assigned to the given case.
     * Throws AccessDeniedException if not.
     * ADMIN role is scoped to their organization.
     */
    public void enforceCaseAccess(UUID caseId) {
        AppUser user = userService.getCurrentUser();
        if (hasRole("ADMIN")) {
            // A missing case used to satisfy "caseRecord == null || sameOrg" and return
            // success, so a nonexistent case id was allowed rather than reported as absent.
            com.crimenet.cases.CaseRecord caseRecord = caseRepository.findById(caseId)
                    .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException(
                            "Case not found: " + caseId));
            if (user.getOrgId().equals(caseRecord.getOrgId())) {
                return;
            }
            log.warn("POLICY_DENIED: Admin {} from org {} attempted cross-tenant access to case {}",
                    user.getId(), user.getOrgId(), caseId);
            throw new AccessDeniedException("Cross-tenant access denied for case: " + caseId);
        }
        if (isAssignedToCase(caseId)) return;

        // Check for active break-glass grant (§11)
        if (breakGlassService.hasActiveGrant(user.getId(), caseId)) {
            log.warn("BREAK_GLASS_ACCESS: User {} accessing case {} via break-glass grant",
                    user.getId(), caseId);
            return;
        }

        log.warn("POLICY_DENIED: User {} attempted to access case {} without assignment",
                user.getId(), caseId);
        throw new AccessDeniedException("Not assigned to case: " + caseId);
    }

    /**
     * Enforce that the current user has the given permission.
     * Throws AccessDeniedException if not.
     */
    public void enforcePermission(String resource, String action) {
        if (hasRole("ADMIN")) return;
        if (!hasPermission(resource, action)) {
            log.warn("POLICY_DENIED: User {} lacks permission {}.{}",
                    userService.getCurrentUser().getId(), resource, action);
            throw new AccessDeniedException("Insufficient permissions for " + resource + "." + action);
        }
    }

    /**
     * Enforce case access AND permission together.
     * Strictly limits break-glass emergency access to VIEW-ONLY actions.
     */
    public void enforceCasePermission(UUID caseId, String resource, String action) {
        AppUser user = userService.getCurrentUser();
        boolean isAssigned = isAssignedToCase(caseId);
        boolean isAdmin = hasRole("ADMIN");

        if (!isAssigned && !isAdmin && breakGlassService.hasActiveGrant(user.getId(), caseId)) {
            if (!("READ".equalsIgnoreCase(action) || "VIEW".equalsIgnoreCase(action))) {
                log.warn("BREAK_GLASS_VIOLATION: User {} attempted mutation {}.{} on case {} under break-glass",
                        user.getId(), resource, action, caseId);
                throw new AccessDeniedException("Break-glass emergency access is strictly VIEW-ONLY. Modifications are rejected.");
            }
        }

        enforcePermission(resource, action);
        enforceCaseAccess(caseId);
    }

    public List<String> getCurrentRoles() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return List.of();
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(a -> a.startsWith("ROLE_") ? a.substring(5) : a)
                .toList();
    }
}
