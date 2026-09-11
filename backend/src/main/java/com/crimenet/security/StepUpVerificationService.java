package com.crimenet.security;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Verifies that the caller genuinely completed a step-up authentication.
 *
 * <p>Break-glass emergency access and MFA-gated share downloads previously accepted
 * any string matching {@code ^MFA-[A-Za-z0-9_\-]{6,64}$}. That is a format check on a
 * value the caller invents — the literal {@code MFA-AAAAAA} satisfied it — so the two
 * controls that guard the most sensitive paths in the system were decorative.
 *
 * <p>Proof of step-up cannot come from the request body. It has to come from the
 * identity provider, in the token it signed: an {@code acr} value the realm only
 * issues for a step-up flow, or an {@code amr} entry naming the factor that was used.
 * The assertion is also time-boxed against {@code auth_time}, so an old token carrying
 * a stale step-up claim does not authorise a new emergency.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8176">RFC 8176 — authentication method reference values</a>
 */
@Slf4j
@Service
public class StepUpVerificationService {

    @Value("${crimenet.security.step-up.accepted-acr:gold,mfa,silver}")
    private List<String> acceptedAcr;

    @Value("${crimenet.security.step-up.accepted-amr:otp,mfa,hwk,swk,face,fpt,pin}")
    private List<String> acceptedAmr;

    /** How recently the step-up must have happened, per {@code auth_time}. */
    @Value("${crimenet.security.step-up.max-age-seconds:300}")
    private long maxAgeSeconds;

    /**
     * Local-demo escape hatch. The bundled Keycloak realm ships no otpPolicy, so no
     * token it issues carries a step-up claim and every gated flow would be unusable.
     * Refused outright in the prod profile.
     */
    @Value("${crimenet.security.step-up.dev-bypass:false}")
    private boolean devBypass;

    @Value("${spring.profiles.active:default}")
    private String activeProfiles;

    @PostConstruct
    void rejectBypassInProduction() {
        if (devBypass && activeProfiles.contains("prod")) {
            throw new IllegalStateException(
                    "crimenet.security.step-up.dev-bypass=true is not permitted in the prod profile. "
                            + "Configure a Keycloak step-up flow that issues an acr or amr claim.");
        }
        if (devBypass) {
            log.warn("STEP_UP_BYPASS_ENABLED: step-up authentication is NOT being verified. "
                    + "This is a local-demo setting and must never reach a deployed environment.");
        }
    }

    /**
     * @param purpose what the step-up is authorising, for the audit trail and the error message
     * @throws AccessDeniedException when the caller's token carries no acceptable, fresh step-up claim
     */
    public void requireStepUp(String purpose) {
        if (devBypass) {
            log.warn("STEP_UP_BYPASSED for {} — dev-bypass is enabled", purpose);
            return;
        }

        Jwt jwt = currentJwt();
        if (jwt == null) {
            throw new AccessDeniedException(
                    "Step-up authentication is required for " + purpose + ", and no bearer token is present.");
        }

        if (!hasAcceptedAcr(jwt) && !hasAcceptedAmr(jwt)) {
            log.warn("STEP_UP_MISSING: subject {} attempted {} with acr={} amr={}",
                    jwt.getSubject(), purpose, jwt.getClaimAsString("acr"), jwt.getClaim("amr"));
            throw new AccessDeniedException(
                    "Step-up authentication is required for " + purpose
                            + ". Re-authenticate with a second factor and retry with the resulting token.");
        }

        assertFresh(jwt, purpose);
    }

    /** True when a step-up claim is present and fresh — for callers that branch rather than reject. */
    public boolean hasStepUp() {
        if (devBypass) {
            return true;
        }
        Jwt jwt = currentJwt();
        if (jwt == null || (!hasAcceptedAcr(jwt) && !hasAcceptedAmr(jwt))) {
            return false;
        }
        Instant authTime = authTime(jwt);
        return authTime == null
                || Duration.between(authTime, Instant.now()).getSeconds() <= maxAgeSeconds;
    }

    // ── claim inspection ─────────────────────────────────────────────────────

    private void assertFresh(Jwt jwt, String purpose) {
        Instant authTime = authTime(jwt);
        if (authTime == null) {
            // Keycloak emits auth_time whenever a step-up flow ran. Its absence alongside
            // a step-up claim means the claim did not come from an interactive authentication.
            log.warn("STEP_UP_NO_AUTH_TIME: subject {} attempted {} with a step-up claim but no auth_time",
                    jwt.getSubject(), purpose);
            throw new AccessDeniedException(
                    "The step-up claim on this token carries no auth_time and cannot be age-verified.");
        }

        long age = Duration.between(authTime, Instant.now()).getSeconds();
        if (age > maxAgeSeconds) {
            log.warn("STEP_UP_STALE: subject {} attempted {} with a step-up {}s old (max {}s)",
                    jwt.getSubject(), purpose, age, maxAgeSeconds);
            throw new AccessDeniedException(
                    "The step-up authentication on this token is " + age + " seconds old; "
                            + maxAgeSeconds + " seconds is the maximum. Re-authenticate and retry.");
        }
    }

    private boolean hasAcceptedAcr(Jwt jwt) {
        String acr = jwt.getClaimAsString("acr");
        if (acr == null || acr.isBlank()) {
            return false;
        }
        return normalised(acceptedAcr).contains(acr.trim().toLowerCase(Locale.ROOT));
    }

    private boolean hasAcceptedAmr(Jwt jwt) {
        Object amr = jwt.getClaim("amr");
        if (!(amr instanceof Collection<?> methods)) {
            return false;
        }
        Set<String> accepted = normalised(acceptedAmr);
        return methods.stream()
                .filter(String.class::isInstance)
                .map(m -> ((String) m).trim().toLowerCase(Locale.ROOT))
                .anyMatch(accepted::contains);
    }

    private Instant authTime(Jwt jwt) {
        Object claim = jwt.getClaim("auth_time");
        if (claim instanceof Instant instant) {
            return instant;
        }
        if (claim instanceof Number seconds) {
            return Instant.ofEpochSecond(seconds.longValue());
        }
        if (claim instanceof String s && !s.isBlank()) {
            try {
                return Instant.ofEpochSecond(Long.parseLong(s.trim()));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Jwt currentJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken token) {
            return token.getToken();
        }
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        return null;
    }

    private Set<String> normalised(List<String> values) {
        return values.stream()
                .map(v -> v.trim().toLowerCase(Locale.ROOT))
                .filter(v -> !v.isEmpty())
                .collect(Collectors.toSet());
    }
}
