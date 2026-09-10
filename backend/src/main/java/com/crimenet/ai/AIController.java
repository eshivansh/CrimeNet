package com.crimenet.ai;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/ai")
@RequiredArgsConstructor
public class AIController {

    private final AIService aiService;

    @PostMapping("/query")
    public ResponseEntity<ApiResponse<AIService.AIQueryResponse>> query(
            @RequestBody AIQueryRequest request) {
        return ResponseEntity.ok(ApiResponse.ok(
                aiService.executeQuery(request.caseId(), request.query())));
    }

    public record AIQueryRequest(UUID caseId, String query) {}
}
