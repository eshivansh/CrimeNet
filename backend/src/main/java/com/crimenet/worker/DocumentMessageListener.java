package com.crimenet.worker;

import com.crimenet.documents.OcrService;
import com.crimenet.infrastructure.MinioStorageService;
import com.crimenet.infrastructure.RabbitMqConfig;
import com.crimenet.search.SearchService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class DocumentMessageListener {

    private final MinioStorageService minioStorageService;
    private final OcrService ocrService;
    private final SearchService searchService;
    private final com.crimenet.documents.DocumentRepository documentRepository;

    private final com.crimenet.infrastructure.IdempotencyRecordRepository idempotencyRecordRepository;

    @RabbitListener(queues = RabbitMqConfig.DOCUMENT_VERSION_CREATED_QUEUE)
    public void handleDocumentVersionCreated(org.springframework.amqp.core.Message message, 
                                             @org.springframework.messaging.handler.annotation.Payload Map<String, Object> payload) {
        String correlationId = (String) message.getMessageProperties().getHeaders().get(com.crimenet.infrastructure.CorrelationIdFilter.CORRELATION_ID_HEADER);
        if (correlationId != null) {
            org.slf4j.MDC.put(com.crimenet.infrastructure.CorrelationIdFilter.CORRELATION_ID_MDC_KEY, correlationId);
        }
        
        log.info("Received DOCUMENT_VERSION_CREATED message. Starting async processing pipeline.");

        // Worker idempotency by job ID (§13): if this exact message was already processed, skip
        String jobId = "OCR-" + payload.getOrDefault("documentId", "") + "-" + payload.getOrDefault("contentHash", "");
        if (idempotencyRecordRepository.existsById(jobId)) {
            log.info("Idempotent skip: job {} already processed. No-op.", jobId);
            return;
        }
        
        try {
            String documentIdStr = (String) payload.get("documentId");
            String caseIdStr = (String) payload.get("caseId");
            String objectKey = (String) payload.get("objectKey");
            String mimeType = (String) payload.get("mimeType");
            String contentHash = (String) payload.get("contentHash");

            if (documentIdStr == null || objectKey == null) {
                log.warn("Message payload missing essential fields. Skipping processing.");
                return;
            }

            UUID documentId = UUID.fromString(documentIdStr);
            UUID caseId = UUID.fromString(caseIdStr);

            // 1. Download file from MinIO
            log.info("Downloading object {} from MinIO for OCR...", objectKey);
            byte[] content = minioStorageService.downloadDocument(objectKey);

            // 2. Extract Text via OCR
            log.info("Extracting text via OcrService for document {}...", documentId);
            String extractedText = ocrService.extractText(content, mimeType);

            // 3. Index to OpenSearch with ACL metadata (§14)
            log.info("Indexing OCR results to OpenSearch for document {}...", documentId);
            com.crimenet.documents.Document doc = documentRepository.findById(documentId).orElse(null);
            String classification = (doc != null) ? doc.getClassification() : "STANDARD";
            
            searchService.indexDocument(documentId, caseId, contentHash, extractedText, 
                    classification, java.util.List.of(), java.util.List.of());

            log.info("Async processing completed for document {}.", documentId);

            // Mark job as completed for idempotency (§13)
            com.crimenet.infrastructure.IdempotencyRecord record = com.crimenet.infrastructure.IdempotencyRecord.builder()
                    .idempotencyKey(jobId)
                    .resourceId(documentIdStr)
                    .statusCode(200)
                    .build();
            idempotencyRecordRepository.save(record);

        } catch (Exception e) {
            log.error("Failed to process document message", e);
            throw new RuntimeException("Async processing failed", e); // Throw to trigger DLQ
        } finally {
            org.slf4j.MDC.remove(com.crimenet.infrastructure.CorrelationIdFilter.CORRELATION_ID_MDC_KEY);
        }
    }
}
