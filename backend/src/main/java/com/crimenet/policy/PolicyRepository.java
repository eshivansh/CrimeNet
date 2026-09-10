package com.crimenet.policy;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, UUID> {
    List<Policy> findByResourceTypeAndStatusOrderByPriorityDesc(String resourceType, String status);
    List<Policy> findByOrgIdAndStatusOrderByPriorityDesc(UUID orgId, String status);
}
