package com.crimenet.identity;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "app_user")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AppUser extends BaseEntity {

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "keycloak_subject", nullable = false, unique = true)
    private String keycloakSubject;

    @Column(name = "department_id")
    private UUID departmentId;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column
    private String email;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    // Hibernate includes updated_at in the INSERT; without this it writes NULL and the
    // NOT NULL constraint rejects the row before the column DEFAULT can apply.
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
