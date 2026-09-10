package com.crimenet.policy;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    List<Permission> findByRoleId(UUID roleId);

    @Query("SELECT p FROM Permission p WHERE p.roleId IN :roleIds")
    List<Permission> findByRoleIdIn(List<UUID> roleIds);

    @Query("SELECT p FROM Permission p WHERE p.roleId IN :roleIds AND p.resource = :resource AND p.action = :action")
    List<Permission> findByRoleIdInAndResourceAndAction(List<UUID> roleIds, String resource, String action);
}
