package com.crimenet.security;

import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Aspect to bridge application identity to PostgreSQL Row-Level Security (RLS).
 * Sets the 'app.current_user_id' parameter at the start of any database transaction.
 */
@Aspect
@Component
@Order(100) // Ensure it runs after transaction starts
@RequiredArgsConstructor
@Slf4j
public class RlsAspect {

    @PersistenceContext
    private EntityManager entityManager;

    private final UserService userService;

    /**
     * Re-entrance guard.
     *
     * <p>This advice resolves the current user through {@link UserService#getCurrentUser()},
     * which is itself {@code @Transactional}. Calling it goes back through the proxy and
     * re-triggers this same advice; once a transaction is active that recursion never
     * terminates and the request dies with a StackOverflowError. The flag lets the nested
     * invocation fall straight through to the target method.
     */
    private static final ThreadLocal<Boolean> BINDING_IN_PROGRESS = new ThreadLocal<>();

    /**
     * Advises class-level {@code @Transactional} as well as method-level.
     *
     * <p>The pointcut was {@code @annotation(...)} alone, which matches annotated methods
     * only. Nine services declare {@code @Transactional} on the class, so every method they
     * inherit it from ran with {@code app.current_user_id} unbound. It happened to work
     * today only because CasePersonService annotates each method and because nested calls
     * into {@code UserService.getCurrentUser} bound the variable as a side effect — meaning
     * the security boundary was established non-deterministically, by an unrelated call.
     * Adding an RLS policy to document or evidence would have silently done nothing.
     */
    @Around("@annotation(org.springframework.transaction.annotation.Transactional)"
            + " || @within(org.springframework.transaction.annotation.Transactional)")
    public Object enforceRls(ProceedingJoinPoint joinPoint) throws Throwable {
        if (TransactionSynchronizationManager.isActualTransactionActive()
                && !Boolean.TRUE.equals(BINDING_IN_PROGRESS.get())) {
            BINDING_IN_PROGRESS.set(Boolean.TRUE);
            try {
                bindCurrentUser();
            } finally {
                BINDING_IN_PROGRESS.remove();
            }
        }
        return joinPoint.proceed();
    }

    private void bindCurrentUser() {
        // Check for a JWT before calling UserService, and return without touching it if
        // there is none. getCurrentUser() is @Transactional, so letting it throw inside an
        // active transaction makes Spring mark that transaction rollback-only — the
        // exception is caught here, but the caller's transaction is already doomed and
        // fails at commit with UnexpectedRollbackException. Scheduled jobs run with no
        // authentication, so this path is hit constantly.
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof Jwt)) {
            log.trace("Skipping RLS binding: no JWT on this thread (system or scheduled job)");
            return;
        }

        AppUser currentUser = null;
        try {
            currentUser = userService.getCurrentUser();
        } catch (Exception e) {
            log.warn("Could not resolve the current user for RLS binding: {}", e.getMessage());
        }

        if (currentUser != null) {
            try {
                // Must be set_config() rather than "SET LOCAL app.current_user_id = ?".
                // SET is a utility statement and cannot take a bind parameter, so the
                // parameterised form fails at the driver and RLS is left unbound.
                // The third argument (true) scopes the setting to the transaction.
                entityManager.createNativeQuery(
                                "SELECT set_config('app.current_user_id', :userId, true)")
                        .setParameter("userId", currentUser.getId().toString())
                        .getSingleResult();
                log.debug("RLS enforced for user: {}", currentUser.getId());
            } catch (Exception e) {
                log.error("Failed to bind app.current_user_id for RLS (user {}). Failing transaction.",
                        currentUser.getId(), e);
                throw new SecurityException("Security context failure: unable to establish row-level security boundary", e);
            }
        }
    }
}
