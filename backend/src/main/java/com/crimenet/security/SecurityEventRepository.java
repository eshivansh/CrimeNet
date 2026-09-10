package com.crimenet.security;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    Page<SecurityEvent> findByResolvedFalseOrderByCreatedAtDesc(Pageable pageable);

    Page<SecurityEvent> findBySeverityOrderByCreatedAtDesc(String severity, Pageable pageable);

    Page<SecurityEvent> findByEventTypeOrderByCreatedAtDesc(String eventType, Pageable pageable);
}
