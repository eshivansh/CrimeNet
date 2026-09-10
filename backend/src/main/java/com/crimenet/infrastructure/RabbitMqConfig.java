package com.crimenet.infrastructure;

import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * RabbitMQ exchange and queue declarations for async processing (§13).
 * Queues are declared now but listeners are Phase 4+.
 */
@Slf4j
@Configuration
public class RabbitMqConfig {

    // Exchanges
    public static final String DOCUMENT_EXCHANGE = "crimenet.document";
    public static final String OCR_EXCHANGE = "crimenet.ocr";
    public static final String AI_EXCHANGE = "crimenet.ai";
    public static final String INTEGRITY_EXCHANGE = "crimenet.integrity";

    // Queues
    public static final String DOCUMENT_UPLOADED_QUEUE = "document.uploaded";
    public static final String DOCUMENT_VERSION_CREATED_QUEUE = "document.version.created";
    public static final String OCR_REQUESTED_QUEUE = "ocr.requested";
    public static final String OCR_COMPLETED_QUEUE = "ocr.completed";
    public static final String AI_ANALYSIS_REQUESTED_QUEUE = "ai.analysis.requested";
    public static final String INTEGRITY_BATCH_READY_QUEUE = "integrity.batch.ready";

    @Bean
    public TopicExchange documentExchange() {
        return new TopicExchange(DOCUMENT_EXCHANGE);
    }

    @Bean
    public TopicExchange ocrExchange() {
        return new TopicExchange(OCR_EXCHANGE);
    }

    @Bean
    public TopicExchange aiExchange() {
        return new TopicExchange(AI_EXCHANGE);
    }

    @Bean
    public TopicExchange integrityExchange() {
        return new TopicExchange(INTEGRITY_EXCHANGE);
    }

    @Bean
    public Queue documentUploadedQueue() {
        return QueueBuilder.durable(DOCUMENT_UPLOADED_QUEUE)
                .withArgument("x-dead-letter-exchange", DOCUMENT_EXCHANGE + ".dlx")
                .build();
    }

    @Bean
    public Queue documentVersionCreatedQueue() {
        return QueueBuilder.durable(DOCUMENT_VERSION_CREATED_QUEUE)
                .withArgument("x-dead-letter-exchange", DOCUMENT_EXCHANGE + ".dlx")
                .build();
    }

    @Bean
    public Queue ocrRequestedQueue() {
        return QueueBuilder.durable(OCR_REQUESTED_QUEUE)
                .withArgument("x-dead-letter-exchange", OCR_EXCHANGE + ".dlx")
                .build();
    }

    @Bean
    public Queue integrityBatchReadyQueue() {
        return QueueBuilder.durable(INTEGRITY_BATCH_READY_QUEUE)
                .withArgument("x-dead-letter-exchange", INTEGRITY_EXCHANGE + ".dlx")
                .build();
    }

    @Bean
    public Binding documentUploadedBinding() {
        return BindingBuilder.bind(documentUploadedQueue()).to(documentExchange()).with("document.uploaded");
    }

    @Bean
    public Binding documentVersionCreatedBinding() {
        return BindingBuilder.bind(documentVersionCreatedQueue()).to(documentExchange()).with("document.version.created");
    }

    @Bean
    public Binding integrityBatchReadyBinding() {
        return BindingBuilder.bind(integrityBatchReadyQueue()).to(integrityExchange()).with("integrity.batch.ready");
    }

    // Dead-Letter Exchanges & Queues (§13)
    @Bean
    public FanoutExchange documentDlx() {
        return new FanoutExchange(DOCUMENT_EXCHANGE + ".dlx");
    }

    @Bean
    public Queue documentDlq() {
        return QueueBuilder.durable(DOCUMENT_EXCHANGE + ".dlq").build();
    }

    @Bean
    public Binding documentDlqBinding() {
        return BindingBuilder.bind(documentDlq()).to(documentDlx());
    }

    @Bean
    public FanoutExchange ocrDlx() {
        return new FanoutExchange(OCR_EXCHANGE + ".dlx");
    }

    @Bean
    public Queue ocrDlq() {
        return QueueBuilder.durable(OCR_EXCHANGE + ".dlq").build();
    }

    @Bean
    public Binding ocrDlqBinding() {
        return BindingBuilder.bind(ocrDlq()).to(ocrDlx());
    }

    @Bean
    public FanoutExchange integrityDlx() {
        return new FanoutExchange(INTEGRITY_EXCHANGE + ".dlx");
    }

    @Bean
    public Queue integrityDlq() {
        return QueueBuilder.durable(INTEGRITY_EXCHANGE + ".dlq").build();
    }

    @Bean
    public Binding integrityDlqBinding() {
        return BindingBuilder.bind(integrityDlq()).to(integrityDlx());
    }

    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        return template;
    }
}
