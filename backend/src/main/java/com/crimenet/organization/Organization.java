package com.crimenet.organization;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "organization")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Organization extends BaseEntity {

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String code;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    // Hibernate includes updated_at in the INSERT; without this it writes NULL and the
    // NOT NULL constraint rejects the row before the column DEFAULT can apply.
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
