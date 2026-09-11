package com.crimenet.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    /** Audiences this API accepts. A token minted for another client is not an API token. */
    @Value("${spring.security.oauth2.resourceserver.jwt.audiences:crimenet-backend,account}")
    private List<String> acceptedAudiences;

    @Value("${crimenet.cors.allowed-origins:http://localhost:3000,http://localhost:5173,http://localhost:8080}")
    private List<String> allowedOrigins;

    /** Swagger is an endpoint inventory; it is not public unless explicitly enabled. */
    @Value("${springdoc.swagger-ui.enabled:false}")
    private boolean swaggerEnabled;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny())
                .contentTypeOptions(contentType -> {})
                .referrerPolicy(referrer -> referrer.policy(
                    org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                // Both bundled apps are entirely inline script and style plus a Google
                // Fonts stylesheet, so this is achievable as-is and blunts any future
                // injection. Tighten to hashes once the inline blocks are extracted.
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; "
                        + "script-src 'self' 'unsafe-inline'; "
                        + "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                        + "font-src 'self' https://fonts.gstatic.com; "
                        + "img-src 'self' data:; "
                        + "connect-src 'self'; "
                        + "frame-ancestors 'none'; "
                        + "base-uri 'self'; "
                        + "form-action 'self'"))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();

                if (swaggerEnabled) {
                    auth.requestMatchers("/swagger-ui/**", "/swagger-ui.html",
                                         "/api-docs/**", "/v3/api-docs/**").permitAll();
                }

                auth
                    // Demo dashboard and mobile UI (static single-page apps served from
                    // src/main/resources/static). The page assets are public; every API
                    // call they make is bearer-authenticated and rejected without a token.
                    .requestMatchers(HttpMethod.GET, "/", "/index.html", "/favicon.ico", "/assets/**", "/mobile/**").permitAll()

                    // Organization — admin only for mutations
                    .requestMatchers(HttpMethod.POST, "/api/v1/organizations/**").hasRole("ADMIN")

                    // Audit — auditor and admin only, and org-scoped inside the service
                    .requestMatchers("/api/v1/audit/**").hasAnyRole("AUDITOR", "ADMIN")

                    // Security events — the denial trail
                    .requestMatchers("/api/v1/security-events/**").hasAnyRole("AUDITOR", "ADMIN")

                    // Integration — admin only
                    .requestMatchers("/api/v1/integrations/**").hasRole("ADMIN")

                    // Provenance anchoring spends gas and allocates batch numbers
                    .requestMatchers(HttpMethod.POST, "/api/v1/provenance/**").hasAnyRole("ADMIN", "AUDITOR")

                    // Destructive evidence-tampering simulation, dev profile only
                    .requestMatchers("/api/dev/**").hasRole("ADMIN")

                    // All other API endpoints require authentication
                    .requestMatchers("/api/**").authenticated()

                    .anyRequest().authenticated();
            })
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthConverter))
            );

        return http.build();
    }

    /**
     * The default decoder validates signature, issuer and expiry — but not {@code aud}.
     * Without this, any token the realm issued for any client, including the public
     * frontend client, was accepted as a CrimeNet API token.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        // Built from the JWK set URI rather than by issuer discovery, so startup does not
        // depend on Keycloak already being up.
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = jwt -> {
            List<String> audience = jwt.getAudience();
            boolean accepted = audience != null && audience.stream().anyMatch(acceptedAudiences::contains);
            if (accepted) {
                return OAuth2TokenValidatorResult.success();
            }
            // Keycloak omits aud when a client has no audience mapper configured; azp
            // identifies the party the token was issued to and is the fallback check.
            String authorizedParty = jwt.getClaimAsString("azp");
            if (authorizedParty != null && acceptedAudiences.contains(authorizedParty)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "This token was not issued for the CrimeNet API. Expected one of "
                            + acceptedAudiences + " in aud or azp.",
                    null));
        };

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, withAudience));
        return decoder;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // Narrowed from "*": credentialed CORS should name the headers it actually needs.
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Correlation-ID", "Idempotency-Key"));
        config.setExposedHeaders(List.of("X-Correlation-ID"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
