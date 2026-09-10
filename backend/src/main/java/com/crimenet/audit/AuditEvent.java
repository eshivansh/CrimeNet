package com.crimenet.audit;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Map;
import java.util.UUID;

/**
 * Append-only audit event — hash-chained, DB trigger protected.
 * Every state-changing operation in the system creates an audit event.
 */
@Entity
@Table(name = "audit_event")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditEvent extends BaseEntity {

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "actor_id")
    private UUID actorId;

    @Column(name = "resource_type")
    private String resourceType;

    @Column(name = "resource_id")
    private UUID resourceId;

    @Column(name = "case_id")
    private UUID caseId;

    @Column(name = "org_id")
    private UUID orgId;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> payload;

    @Column(name = "payload_hash", nullable = false)
    private String payloadHash;

    @Column(name = "previous_event_hash")
    private String previousEventHash;

    @Column(name = "event_hash", nullable = false)
    private String eventHash;
}
