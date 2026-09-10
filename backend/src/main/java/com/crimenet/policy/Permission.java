package com.crimenet.policy;

import com.crimenet.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "permission", uniqueConstraints = @UniqueConstraint(columnNames = {"role_id", "resource", "action"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Permission extends BaseEntity {

    @Column(name = "role_id", nullable = false)
    private UUID roleId;

    @Column(nullable = false)
    private String resource;

    @Column(nullable = false)
    private String action;
}
