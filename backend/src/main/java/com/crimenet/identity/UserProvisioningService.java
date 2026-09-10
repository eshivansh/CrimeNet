package com.crimenet.identity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Creates the internal user record for a Keycloak subject on first sight.
 *
 * <p>This lives in its own bean for one reason: the provisioning insert must commit in its
 * own transaction, and {@code REQUIRES_NEW} is only honoured when the call crosses a proxy
 * boundary. Calling it from a sibling method of {@link UserService} would be a
 * self-invocation and would silently join the caller's transaction instead.
 *
 * <p>Why it must commit separately: a user's very first authenticated request is usually
 * also an audited business action. The identity row would then be inserted inside that
 * outer transaction, while {@code AuditService} — which deliberately runs REQUIRES_NEW so
 * audit survives rollback — opens a second transaction that cannot see it. That second
 * transaction then either violates the audit foreign key, or tries to provision the same
 * keycloak_subject itself and blocks on the unique index while the outer transaction waits
 * on it: a deadlock that only ever appears on a user's first action, which is to say on
 * every clean demo run.
 *
 * <p>Committing identity up front removes the ordering problem entirely: by the time any
 * nested transaction looks for the user, the row is durably there.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserProvisioningService {

    private final AppUserRepository appUserRepository;

    /** Organization to attach new users to until an org claim is available on the token. */
    private static final UUID DEFAULT_ORG_ID =
            UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AppUser provision(Jwt jwt) {
        String subject = jwt.getSubject();

        String name = jwt.getClaimAsString("preferred_username");
        if (name == null) {
            name = jwt.getClaimAsString("name");
        }
        if (name == null) {
            name = subject;
        }

        AppUser user = AppUser.builder()
                .keycloakSubject(subject)
                .displayName(name)
                .email(jwt.getClaimAsString("email"))
                .orgId(DEFAULT_ORG_ID)
                .status("ACTIVE")
                .build();

        try {
            AppUser saved = appUserRepository.save(user);
            log.info("Auto-provisioned user from Keycloak: {} ({})", name, subject);
            return saved;
        } catch (DataIntegrityViolationException e) {
            // Two concurrent first requests can both reach this point; the unique index on
            // keycloak_subject lets exactly one win. Re-read rather than failing the loser.
            log.debug("Concurrent provisioning for subject {}, reading the winning row", subject);
            return appUserRepository.findByKeycloakSubject(subject)
                    .orElseThrow(() -> e);
        }
    }
}
