package com.crimenet.infrastructure;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

/**
 * Service for publishing async events to RabbitMQ.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RabbitMqPublisher {

    private final RabbitTemplate rabbitTemplate;

    public void publishDocumentVersionCreated(Object payload) {
        log.info("Publishing DOCUMENT_VERSION_CREATED event...");
        String correlationId = org.slf4j.MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY);
        try {
            rabbitTemplate.convertAndSend(
                    RabbitMqConfig.DOCUMENT_EXCHANGE,
                    "document.version.created",
                    payload,
                    message -> {
                        if (correlationId != null) {
                            message.getMessageProperties().setHeader(CorrelationIdFilter.CORRELATION_ID_HEADER, correlationId);
                        }
                        return message;
                    }
            );
        } catch (Exception e) {
            log.error("Failed to publish to RabbitMQ: {}", e.getMessage(), e);
            // Non-fatal, depending on business requirements we might want to throw or queue for retry
        }
    }
    
    public void publishDocumentUploaded(Object payload) {
        log.info("Publishing DOCUMENT_UPLOADED event...");
        try {
            rabbitTemplate.convertAndSend(
                    RabbitMqConfig.DOCUMENT_EXCHANGE,
                    "document.uploaded",
                    payload
            );
        } catch (Exception e) {
            log.error("Failed to publish to RabbitMQ: {}", e.getMessage(), e);
        }
    }
}
