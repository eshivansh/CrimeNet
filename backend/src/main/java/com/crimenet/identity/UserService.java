package com.crimenet.identity;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final AppUserRepository appUserRepository;
    private final UserProvisioningService userProvisioningService;

    /**
     * Resolve the current authenticated user from the JWT subject claim.
     * Auto-provisions the user if they exist in Keycloak but not yet in the DB.
     */
    @Transactional
    public AppUser getCurrentUser() {
        Jwt jwt = getCurrentJwt();
        String subject = jwt.getSubject();

        AppUser user = appUserRepository.findByKeycloakSubject(subject)
                .orElseGet(() -> userProvisioningService.provision(jwt));

        // AppUser.status was stored and never consulted by any code path, so suspending or
        // terminating an officer here changed nothing: they kept full case, evidence and
        // document access for as long as their Keycloak token remained valid.
        if (user.getStatus() != null && !"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            log.warn("INACTIVE_USER_REJECTED: subject {} resolved to user {} with status {}",
                    subject, user.getId(), user.getStatus());
            throw new org.springframework.security.access.AccessDeniedException(
                    "This account is " + user.getStatus() + " and cannot access CrimeNet.");
        }

        return user;
    }

    /**
     * Get user by internal ID.
     */
    public AppUser getUser(UUID id) {
        return appUserRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + id));
    }

    /**
     * Get user by Keycloak subject.
     */
    public AppUser getUserBySubject(String subject) {
        return appUserRepository.findByKeycloakSubject(subject)
                .orElseThrow(() -> new EntityNotFoundException("User not found for subject: " + subject));
    }

    public List<AppUser> listUsers(UUID orgId) {
        return appUserRepository.findByOrgId(orgId);
    }

    /**
     * Auto-provisions a user from Keycloak JWT claims on first login.
     *
     * <p>Delegates to {@link UserProvisioningService} so the insert commits in its own
     * transaction. Doing it inline here would join the caller's transaction and deadlock
     * against the REQUIRES_NEW audit write on a user's first action.
     */
    public AppUser autoProvisionUser(Jwt jwt) {
        return userProvisioningService.provision(jwt);
    }

    private Jwt getCurrentJwt() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof Jwt jwt) {
            return jwt;
        }
        throw new IllegalStateException("Expected JWT authentication but got: " + principal.getClass());
    }
}
