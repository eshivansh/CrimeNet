package com.crimenet.cases;

import com.crimenet.common.ApiResponse;
import com.crimenet.common.PageResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/cases")
@RequiredArgsConstructor
public class CaseController {

    private final CaseService caseService;

    @PostMapping
    public ResponseEntity<ApiResponse<CaseRecord>> create(@Valid @RequestBody CreateCaseRequest request) {
        CaseRecord caseRecord = caseService.createCase(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(caseRecord));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<CaseRecord>> get(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(caseService.getCase(id)));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<PageResponse<CaseRecord>>> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<CaseRecord> result = caseService.listMyCases(
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
        PageResponse<CaseRecord> response = PageResponse.<CaseRecord>builder()
                .content(result.getContent())
                .page(result.getNumber())
                .size(result.getSize())
                .totalElements(result.getTotalElements())
                .totalPages(result.getTotalPages())
                .last(result.isLast())
                .build();
        return ResponseEntity.ok(ApiResponse.ok(response));
    }

    @PostMapping("/{id}/assignments")
    public ResponseEntity<ApiResponse<CaseAssignment>> assign(
            @PathVariable UUID id,
            @RequestBody AssignUserRequest request) {
        CaseAssignment assignment = caseService.assignUser(id, request.userId(), request.roleInCase());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(assignment));
    }

    @GetMapping("/{id}/assignments")
    public ResponseEntity<ApiResponse<List<CaseAssignment>>> getAssignments(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(caseService.getCaseAssignments(id)));
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<ApiResponse<CaseRecord>> updateStatus(
            @PathVariable UUID id,
            @RequestBody UpdateStatusRequest request) {
        return ResponseEntity.ok(ApiResponse.ok(caseService.updateStatus(id, request.status())));
    }

    public record AssignUserRequest(UUID userId, String roleInCase) {}
    public record UpdateStatusRequest(String status) {}
}
