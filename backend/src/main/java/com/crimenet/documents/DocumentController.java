package com.crimenet.documents;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class DocumentController {

    private final DocumentService documentService;

    @PostMapping(value = "/cases/{caseId}/documents", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<Document>> upload(
            @PathVariable UUID caseId,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestParam("file") MultipartFile file,
            @RequestParam("docType") String docType,
            @RequestParam(value = "title", required = false) String title,
            @RequestParam(value = "classification", required = false) String classification) throws IOException {
        Document doc = documentService.createDocument(caseId, docType, title, classification, file, idempotencyKey);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(doc));
    }

    @GetMapping("/cases/{caseId}/documents")
    public ResponseEntity<ApiResponse<List<Document>>> listForCase(@PathVariable UUID caseId) {
        return ResponseEntity.ok(ApiResponse.ok(documentService.listDocumentsForCase(caseId)));
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<ApiResponse<Document>> get(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(documentService.getDocument(id)));
    }

    @GetMapping("/documents/{id}/versions")
    public ResponseEntity<ApiResponse<List<DocumentVersion>>> versions(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(documentService.getVersions(id)));
    }

    @PostMapping(value = "/documents/{id}/versions", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<DocumentVersion>> addVersion(
            @PathVariable UUID id,
            @RequestParam("file") MultipartFile file) throws IOException {
        DocumentVersion version = documentService.addDocumentVersion(id, file);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(version));
    }

    @GetMapping("/documents/{id}/integrity")
    public ResponseEntity<ApiResponse<DocumentService.IntegrityCheckResult>> verify(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(documentService.verifyIntegrity(id)));
    }

    @GetMapping("/documents/{id}/download")
    public ResponseEntity<ApiResponse<String>> downloadLatest(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(documentService.getDocumentDownloadUrl(id, null)));
    }

    @GetMapping("/documents/{id}/versions/{versionId}/download")
    public ResponseEntity<ApiResponse<String>> downloadVersion(
            @PathVariable UUID id,
            @PathVariable UUID versionId) {
        return ResponseEntity.ok(ApiResponse.ok(documentService.getDocumentDownloadUrl(id, versionId)));
    }
}
