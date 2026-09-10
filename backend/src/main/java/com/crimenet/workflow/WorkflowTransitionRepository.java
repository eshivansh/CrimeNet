package com.crimenet.workflow;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface WorkflowTransitionRepository extends JpaRepository<WorkflowTransition, UUID> {
    List<WorkflowTransition> findByResourceIdOrderByTransitionedAtDesc(UUID resourceId);
    List<WorkflowTransition> findByCaseIdOrderByTransitionedAtDesc(UUID caseId);
}
