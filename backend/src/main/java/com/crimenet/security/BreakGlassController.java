package com.crimenet.security;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/break-glass")
@RequiredArgsConstructor
public class BreakGlassController {

    private final BreakGlassService breakGlassService;

    @PostMapping
    public ResponseEntity<ApiResponse<BreakGlassGrant>> request(@RequestBody BreakGlassRequest request) {
        if (request.mfaToken() == null || request.mfaToken().isBlank()) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Step-up MFA verification is mandatory to request emergency break-glass access");
        }
        BreakGlassGrant grant = breakGlassService.requestBreakGlass(request.caseId(), request.reason(), request.mfaToken());
        return ResponseEntity.ok(ApiResponse.ok(grant));
    }

    @DeleteMapping("/{grantId}")
    public ResponseEntity<ApiResponse<BreakGlassGrant>> revoke(@PathVariable UUID grantId) {
        return ResponseEntity.ok(ApiResponse.ok(breakGlassService.revokeGrant(grantId)));
    }

    public record BreakGlassRequest(UUID caseId, String reason, String mfaToken) {}
}
