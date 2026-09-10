package com.crimenet.ai;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AIReferenceRepository extends JpaRepository<AIReference, UUID> {
    List<AIReference> findByResultId(UUID resultId);
}
