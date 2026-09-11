package com.crimenet.sharing;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/shares")
@RequiredArgsConstructor
public class ShareController {

    private final ShareService shareService;

    @PostMapping
    public ResponseEntity<ApiResponse<SharePackage>> create(
            @jakarta.validation.Valid @RequestBody ShareService.CreateShareRequest request) {
        SharePackage pkg = shareService.createShare(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(pkg));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<SharePackage>> revoke(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(shareService.revokeShare(id)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<SharePackage>> get(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(shareService.getShare(id)));
    }

    @GetMapping("/case/{caseId}")
    public ResponseEntity<ApiResponse<List<SharePackage>>> listForCase(@PathVariable UUID caseId) {
        return ResponseEntity.ok(ApiResponse.ok(shareService.listSharesForCase(caseId)));
    }

    /**
     * The mfaToken query parameter is gone. Step-up is read from the bearer token's own
     * claims, so nothing sensitive rides in a URL that lands in access and proxy logs.
     */
    @GetMapping("/{id}/download/{documentVersionId}")
    public ResponseEntity<ApiResponse<ShareService.ShareDownloadResponse>> download(
            @PathVariable UUID id,
            @PathVariable UUID documentVersionId) {
        ShareService.ShareDownloadResponse response = shareService.generateDownloadUrl(id, documentVersionId);
        return ResponseEntity.ok(ApiResponse.ok(response));
    }
}
