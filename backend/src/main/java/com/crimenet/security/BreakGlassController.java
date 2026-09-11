package com.crimenet.security;

import com.crimenet.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Emergency access (§11).
 *
 * <p>The request body no longer carries an "mfaToken". Proof of step-up comes from the
 * bearer token's own {@code acr}/{@code amr} claims — see {@link StepUpVerificationService} —
 * because a value the caller supplies can never establish that the caller authenticated.
 */
@RestController
@RequestMapping("/api/v1/break-glass")
@RequiredArgsConstructor
public class BreakGlassController {

    private final BreakGlassService breakGlassService;

    @PostMapping
    @PreAuthorize("hasAnyRole('INVESTIGATOR', 'SUPERVISOR', 'FORENSIC_OFFICER', 'PROSECUTOR', 'ADMIN')")
    public ResponseEntity<ApiResponse<BreakGlassGrant>> request(@Valid @RequestBody BreakGlassRequest request) {
        BreakGlassGrant grant = breakGlassService.requestBreakGlass(request.caseId(), request.reason());
        return ResponseEntity.ok(ApiResponse.ok(grant));
    }

    @DeleteMapping("/{grantId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<BreakGlassGrant>> revoke(@PathVariable UUID grantId) {
        return ResponseEntity.ok(ApiResponse.ok(breakGlassService.revokeGrant(grantId)));
    }

    public record BreakGlassRequest(
            @NotNull(message = "caseId is required")
            UUID caseId,

            @NotNull(message = "A justification reason is required")
            @Size(min = 10, max = 2000, message = "The justification must be at least 10 characters")
            String reason
    ) {}
}
