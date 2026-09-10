package com.crimenet.ai;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.policy.PolicyEvaluationService;
import com.crimenet.policy.SecurityContext;
import com.crimenet.search.SearchResponseDto;
import com.crimenet.search.SearchService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * AI/RAG Service — permission-aware retrieval-augmented generation (§14, §15).
 *
 * Key architectural rules:
 *   1. AI is READ-ONLY. It has NO write path to document, evidence, or custody tables.
 *   2. Retrieved chunks are pre-filtered by ABAC (case assignment + classification)
 *      BEFORE they enter the AI context — never post-filtered.
 *   3. Every AI job records full provenance: query, model, retrieved chunks, response.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AIService {

    private final AIJobRepository aiJobRepository;
    private final AIResultRepository aiResultRepository;
    private final AIReferenceRepository aiReferenceRepository;
    private final SearchService searchService;
    private final PolicyEvaluationService policyService;
    private final UserService userService;
    private final AuditService auditService;

    /**
     * Execute a permission-aware RAG query.
     *
     * Flow (§14):
     *   1. Authenticate + authorize
     *   2. Build authorized resource set (case assignment + classification)
     *   3. Hybrid search with ACL filter applied IN the query (pre-retrieval)
     *   4. Feed only authorized chunks to RAG
     *   5. Record provenance (job + result + references)
     */
    @Transactional
    public AIQueryResponse executeQuery(UUID caseId, String queryText) {
        // 1. Enforce case access
        policyService.enforceCasePermission(caseId, "AI", "QUERY");
        AppUser currentUser = userService.getCurrentUser();
        SecurityContext context = policyService.buildContext();

        // 2. Create job record (provenance starts here)
        AIJob job = AIJob.builder()
                .caseId(caseId)
                .requestedBy(currentUser.getId())
                .jobType("RAG_QUERY")
                .queryText(queryText)
                .modelName("mock-llm")
                .modelVersion("1.0")
                .status("PROCESSING")
                .build();
        job = aiJobRepository.save(job);

        // 3. Search with pre-retrieval ABAC filter (§14 — the critical part)
        //    Only documents from cases this user is assigned to are candidates.
        List<SearchResponseDto> searchResults = searchService.searchDocuments(
                queryText, context.getAssignedCaseIds());

        // 4. Mock RAG generation (real implementation would call an LLM API)
        String generatedResponse = mockRagGeneration(queryText, searchResults);

        // 5. Save result
        AIResult result = AIResult.builder()
                .jobId(job.getId())
                .responseText(generatedResponse)
                .tokenCount(generatedResponse.split("\\s+").length)
                .confidenceScore(0.85)
                .build();
        result = aiResultRepository.save(result);

        // 6. Save references (which documents were actually retrieved/cited)
        List<AIReference> references = new ArrayList<>();
        for (SearchResponseDto hit : searchResults) {
            AIReference ref = AIReference.builder()
                    .resultId(result.getId())
                    .documentId(hit.documentId())
                    .relevanceScore((double) hit.score())
                    .build();
            references.add(aiReferenceRepository.save(ref));
        }

        // 7. Mark job complete
        job.setStatus("COMPLETED");
        job.setCompletedAt(Instant.now());
        aiJobRepository.save(job);

        // 8. Audit
        auditService.record("AI_QUERY_EXECUTED", currentUser.getId(), job.getId(), caseId,
                Map.of("queryText", queryText, "resultCount", searchResults.size(),
                        "model", "mock-llm"));

        log.info("AI query completed for case {} by user {}. {} documents cited.",
                caseId, currentUser.getId(), references.size());

        return new AIQueryResponse(
                job.getId(),
                generatedResponse,
                references.stream().map(r -> new AIQueryResponse.Citation(
                        r.getDocumentId(), r.getRelevanceScore()
                )).toList()
        );
    }

    private String mockRagGeneration(String query, List<SearchResponseDto> context) {
        if (context.isEmpty()) {
            return "No authorized documents found matching your query. " +
                    "You may not have access to relevant case materials.";
        }
        return String.format(
                "Based on %d authorized document(s) retrieved for your query \"%s\": " +
                "This is a mock RAG response. In production, this would be generated by an LLM " +
                "using only the pre-filtered, authorized document chunks as context. " +
                "No unauthorized content has entered this response pipeline.",
                context.size(), query
        );
    }

    public record AIQueryResponse(
            UUID jobId,
            String response,
            List<Citation> citations
    ) {
        public record Citation(UUID documentId, Double relevanceScore) {}
    }
}
