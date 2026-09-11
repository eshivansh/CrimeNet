package com.crimenet.common;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Base entity with common fields shared across all domain entities.
 */
@MappedSuperclass
@Getter
@Setter
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;

    /**
     * Assigns the creation timestamp unless one was set deliberately.
     *
     * <p>This was {@code @CreationTimestamp}, whose generator always overwrites on insert.
     * AuditEvent needs {@code createdAt} inside its chain hash, which means the value that
     * is hashed has to be the value that is stored — an overwrite a moment later would
     * make every event fail its own verification. Behaviour is otherwise unchanged: an
     * entity that does not set the field still gets the insert-time instant.
     */
    @PrePersist
    void assignCreatedAt() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
