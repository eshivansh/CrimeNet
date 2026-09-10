package com.crimenet.ai;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AIJobRepository extends JpaRepository<AIJob, UUID> {
}
