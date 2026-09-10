package com.crimenet.cases;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "case_person")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CasePerson extends BaseEntity {

    @Column(name = "case_id", nullable = false)
    private UUID caseId;

    @Column(name = "person_name", nullable = false)
    private String personName;

    @Column(name = "role_type", nullable = false)
    private String roleType;  // VICTIM | WITNESS | ACCUSED | INFORMANT

    @Column(name = "id_type")
    private String idType;  // AADHAAR | PAN | PASSPORT | OTHER

    @Convert(converter = com.crimenet.security.EncryptedStringConverter.class)
    @Column(name = "id_number_encrypted")
    private String idNumberEncrypted;

    @Convert(converter = com.crimenet.security.EncryptedStringConverter.class)
    @Column(name = "contact_encrypted")
    private String contactEncrypted;

    @Convert(converter = com.crimenet.security.EncryptedStringConverter.class)
    @Column(name = "address_encrypted")
    private String addressEncrypted;

    @Column
    private String notes;

    @Column(nullable = false)
    @Builder.Default
    private String status = "ACTIVE";

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;
}
