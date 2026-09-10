package com.crimenet.provenance;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/provenance")
@RequiredArgsConstructor
public class ProvenanceController {

    private final AnchorService anchorService;

    @PostMapping("/anchor")
    public ResponseEntity<ApiResponse<String>> triggerAnchor() {
        anchorService.anchorPendingEvents();
        return ResponseEntity.ok(ApiResponse.ok("Anchor batch triggered"));
    }

    @GetMapping("/verify/{batchNumber}")
    public ResponseEntity<ApiResponse<AnchorService.VerificationResult>> verifyBatch(
            @PathVariable long batchNumber) {
        return ResponseEntity.ok(ApiResponse.ok(anchorService.verifyBatch(batchNumber)));
    }

    @GetMapping("/verify")
    public ResponseEntity<ApiResponse<List<AnchorService.VerificationResult>>> verifyAll() {
        return ResponseEntity.ok(ApiResponse.ok(anchorService.verifyAll()));
    }
}
