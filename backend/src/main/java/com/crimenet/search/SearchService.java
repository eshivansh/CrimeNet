package com.crimenet.search;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OpenSearch integration with full ACL indexing and pre-retrieval ABAC filtering (§14).
 *
 * Every OpenSearch document includes ACL fields (case_id, classification, authorized_roles[],
 * authorized_user_ids[]) and every query includes a MANDATORY bool filter on those fields
 * built server-side — restricted documents are excluded from the candidate set BEFORE
 * ranking/similarity is computed, never filtered from results afterward.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SearchService {

    private final RestHighLevelClient openSearchClient;
    private static final String INDEX_NAME = "crimenet-documents";

    /**
     * Index a document with full ACL metadata for pre-retrieval filtering (§14).
     */
    public void indexDocument(UUID documentId, UUID caseId, String hash, String text,
                              String classification, List<String> authorizedRoles,
                              List<String> authorizedUserIds) {
        try {
            IndexRequest request = new IndexRequest(INDEX_NAME)
                    .id(documentId.toString())
                    .source(Map.of(
                            "documentId", documentId.toString(),
                            "caseId", caseId.toString(),
                            "hash", hash,
                            "text", text,
                            "classification", classification != null ? classification : "STANDARD",
                            "authorizedRoles", authorizedRoles != null ? authorizedRoles : List.of(),
                            "authorizedUserIds", authorizedUserIds != null ? authorizedUserIds : List.of()
                    ), XContentType.JSON);

            IndexResponse response = openSearchClient.index(request, RequestOptions.DEFAULT);
            log.info("Indexed document {} with ACL fields. Result: {}", documentId, response.getResult());
        } catch (IOException e) {
            log.error("Failed to index document {} in OpenSearch", documentId, e);
        }
    }

    /**
     * Backward-compatible overload (used by DocumentMessageListener).
     */
    public void indexDocument(UUID documentId, UUID caseId, String hash, String text) {
        indexDocument(documentId, caseId, hash, text, "STANDARD", List.of(), List.of());
    }

    /**
     * Full-text search with strict pre-retrieval ABAC filtering (§14).
     *
     * Filtering is applied IN the OpenSearch query itself via bool filter clauses,
     * not as a post-hoc step. This means restricted documents are excluded from the
     * candidate set before ranking — the search engine never "sees" them.
     */
    public List<SearchResponseDto> searchDocuments(String query, List<UUID> allowedCaseIds) {
        return searchDocuments(query, allowedCaseIds, null, null);
    }

    /**
     * Full search with case, classification, and role filtering.
     */
    public List<SearchResponseDto> searchDocuments(String query, List<UUID> allowedCaseIds,
                                                    String requiredClassification,
                                                    List<String> userRoles) {
        if (allowedCaseIds == null || allowedCaseIds.isEmpty()) {
            return new ArrayList<>(); // Zero-trust: no cases = no results
        }

        try {
            SearchRequest searchRequest = new SearchRequest(INDEX_NAME);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                    .must(QueryBuilders.matchQuery("text", query));

            // These filters must target the ".keyword" sub-fields, not the bare field names.
            // The index has no explicit mapping, so OpenSearch maps these dynamically as
            // analysed `text` with a `keyword` sub-field. A term/terms query on the analysed
            // field compares against individual tokens: the standard analyser splits a UUID on
            // its hyphens, so "65e377f3-e7bf-..." is never a token and the mandatory case
            // filter matched nothing — every search silently returned zero results.

            // MANDATORY filter: case_id must be in the user's assigned set
            List<String> caseIdStrings = allowedCaseIds.stream().map(UUID::toString).toList();
            boolQuery.filter(QueryBuilders.termsQuery("caseId.keyword", caseIdStrings));

            // Classification filter (if specified)
            if (requiredClassification != null) {
                boolQuery.filter(QueryBuilders.termQuery("classification.keyword", requiredClassification));
            }

            // Role-based filter (if specified)
            if (userRoles != null && !userRoles.isEmpty()) {
                boolQuery.filter(QueryBuilders.termsQuery("authorizedRoles.keyword", userRoles));
            }

            sourceBuilder.query(boolQuery);
            searchRequest.source(sourceBuilder);

            SearchResponse response = openSearchClient.search(searchRequest, RequestOptions.DEFAULT);
            List<SearchResponseDto> results = new ArrayList<>();

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();
                results.add(new SearchResponseDto(
                        UUID.fromString((String) source.get("documentId")),
                        UUID.fromString((String) source.get("caseId")),
                        (String) source.get("hash"),
                        hit.getScore()
                ));
            }

            log.info("Search '{}' yielded {} results (filtered by {} cases)", query, results.size(), allowedCaseIds.size());
            return results;

        } catch (IOException e) {
            log.error("Failed to execute search query: {}", query, e);
            throw new RuntimeException("Search execution failed", e);
        }
    }
}
