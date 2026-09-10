package com.crimenet.ai;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AIResultRepository extends JpaRepository<AIResult, UUID> {
    Optional<AIResult> findByJobId(UUID jobId);
}
