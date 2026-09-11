package com.crimenet.audit;

import com.crimenet.common.ApiResponse;
import com.crimenet.common.PageResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditService auditService;

    /** An unbounded size parameter let one request materialise the whole table. */
    private static final int MAX_PAGE_SIZE = 200;

    private static int clampSize(int size) {
        return Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
    }

    @GetMapping
    public ResponseEntity<ApiResponse<PageResponse<AuditEvent>>> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<AuditEvent> result = auditService.listEvents(
                PageRequest.of(Math.max(page, 0), clampSize(size), Sort.by(Sort.Direction.DESC, "createdAt")));
        return ResponseEntity.ok(ApiResponse.ok(toPageResponse(result)));
    }

    @GetMapping("/case/{caseId}")
    public ResponseEntity<ApiResponse<PageResponse<AuditEvent>>> listByCase(
            @PathVariable UUID caseId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<AuditEvent> result = auditService.listEventsByCase(caseId,
                PageRequest.of(Math.max(page, 0), clampSize(size), Sort.by(Sort.Direction.DESC, "createdAt")));
        return ResponseEntity.ok(ApiResponse.ok(toPageResponse(result)));
    }

    @GetMapping("/type/{eventType}")
    public ResponseEntity<ApiResponse<PageResponse<AuditEvent>>> listByType(
            @PathVariable String eventType,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<AuditEvent> result = auditService.listEventsByType(eventType,
                PageRequest.of(Math.max(page, 0), clampSize(size), Sort.by(Sort.Direction.DESC, "createdAt")));
        return ResponseEntity.ok(ApiResponse.ok(toPageResponse(result)));
    }

    /**
     * Walks the most recent events, recomputing each hash from its own stored fields and
     * checking the linkage. Nothing previously verified the chain through any API.
     */
    @GetMapping("/verify-chain")
    public ResponseEntity<ApiResponse<AuditService.ChainVerificationResult>> verifyChain(
            @RequestParam(defaultValue = "500") int limit) {
        int bounded = Math.min(Math.max(limit, 1), 5000);
        return ResponseEntity.ok(ApiResponse.ok(auditService.verifyChain(bounded)));
    }

    private <T> PageResponse<T> toPageResponse(Page<T> page) {
        return PageResponse.<T>builder()
                .content(page.getContent())
                .page(page.getNumber())
                .size(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .last(page.isLast())
                .build();
    }
}
