package com.crimenet.cases;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "case_record")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CaseRecord extends BaseEntity {

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "case_number", nullable = false, unique = true)
    private String caseNumber;

    @Column
    private String title;

    @Column
    private String description;

    @Column(name = "fir_id")
    private String firId;

    @Column(name = "icjs_case_id")
    private String icjsCaseId;

    @Column(nullable = false)
    @Builder.Default
    private String classification = "STANDARD";

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    // Hibernate includes updated_at in the INSERT; without this it writes NULL and the
    // NOT NULL constraint rejects the row before the column DEFAULT can apply.
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
