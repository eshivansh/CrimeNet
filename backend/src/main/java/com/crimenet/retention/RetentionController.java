package com.crimenet.retention;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class RetentionController {

    private final RetentionService retentionService;

    @PostMapping("/cases/{caseId}/legal-holds")
    public ResponseEntity<ApiResponse<LegalHold>> applyHold(
            @PathVariable UUID caseId,
            @RequestBody ApplyHoldRequest request) {
        LegalHold hold = retentionService.applyLegalHold(caseId, request.reason());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(hold));
    }

    @PostMapping("/legal-holds/{id}/release")
    public ResponseEntity<ApiResponse<LegalHold>> releaseHold(
            @PathVariable UUID id,
            @RequestBody ReleaseHoldRequest request) {
        return ResponseEntity.ok(ApiResponse.ok(retentionService.releaseLegalHold(id, request.reason())));
    }

    @GetMapping("/cases/{caseId}/legal-holds")
    public ResponseEntity<ApiResponse<List<LegalHold>>> getActiveHolds(@PathVariable UUID caseId) {
        return ResponseEntity.ok(ApiResponse.ok(retentionService.getActiveHolds(caseId)));
    }

    @PostMapping("/documents/{documentId}/archive")
    public ResponseEntity<ApiResponse<String>> archiveDocument(@PathVariable UUID documentId) {
        retentionService.archiveDocument(documentId);
        return ResponseEntity.ok(ApiResponse.ok("Document archived successfully"));
    }

    public record ApplyHoldRequest(String reason) {}
    public record ReleaseHoldRequest(String reason) {}
}
