package com.crimenet.evidence;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class EvidenceController {

    private final EvidenceService evidenceService;

    @PostMapping("/evidence")
    public ResponseEntity<ApiResponse<Evidence>> register(
            @RequestBody EvidenceService.RegisterEvidenceRequest request) {
        Evidence evidence = evidenceService.registerEvidence(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(evidence));
    }

    @GetMapping("/evidence/{id}")
    public ResponseEntity<ApiResponse<Evidence>> get(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(evidenceService.getEvidence(id)));
    }

    @GetMapping("/cases/{caseId}/evidence")
    public ResponseEntity<ApiResponse<List<Evidence>>> listForCase(@PathVariable UUID caseId) {
        return ResponseEntity.ok(ApiResponse.ok(evidenceService.listEvidenceForCase(caseId)));
    }

    @PostMapping("/evidence/{id}/custody")
    public ResponseEntity<ApiResponse<CustodyEvent>> transferCustody(
            @PathVariable UUID id,
            @RequestBody EvidenceService.TransferCustodyRequest request) {
        CustodyEvent event = evidenceService.transferCustody(id, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(event));
    }

    @GetMapping("/evidence/{id}/chain")
    public ResponseEntity<ApiResponse<List<CustodyEvent>>> getCustodyChain(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(evidenceService.getCustodyChain(id)));
    }

    @PostMapping("/evidence/{id}/artifacts")
    public ResponseEntity<ApiResponse<EvidenceArtifact>> addArtifact(
            @PathVariable UUID id,
            @RequestParam("artifactType") String artifactType,
            @RequestParam(value = "description", required = false) String description,
            @RequestParam("file") MultipartFile file) throws IOException {
        EvidenceArtifact artifact = evidenceService.addArtifact(id, artifactType, description, file);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(artifact));
    }

    @GetMapping("/evidence/{id}/artifacts")
    public ResponseEntity<ApiResponse<List<EvidenceArtifact>>> listArtifacts(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(evidenceService.listArtifacts(id)));
    }

    @GetMapping("/evidence/{id}/artifacts/{artifactId}/download")
    public ResponseEntity<ApiResponse<String>> downloadArtifact(
            @PathVariable UUID id,
            @PathVariable UUID artifactId) {
        return ResponseEntity.ok(ApiResponse.ok(evidenceService.getArtifactDownloadUrl(id, artifactId)));
    }
}
