package com.crimenet.search;

import com.crimenet.common.ApiResponse;
import com.crimenet.policy.PolicyEvaluationService;
import com.crimenet.policy.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/search")
@RequiredArgsConstructor
public class SearchController {

    private final SearchService searchService;
    private final PolicyEvaluationService policyService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<SearchResponseDto>>> searchDocuments(@RequestParam("q") String query) {
        // 1. Get ABAC security context for current user
        SecurityContext context = policyService.buildContext();

        // 2. Pass assigned case IDs to search service for strict filtering
        List<SearchResponseDto> results = searchService.searchDocuments(query, context.getAssignedCaseIds());

        return ResponseEntity.ok(ApiResponse.ok(results));
    }
}
