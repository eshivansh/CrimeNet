package com.crimenet.security;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface BreakGlassRepository extends JpaRepository<BreakGlassGrant, UUID> {

    List<BreakGlassGrant> findByGrantedToAndCaseIdAndStatus(UUID grantedTo, UUID caseId, String status);

    List<BreakGlassGrant> findByStatusAndExpiresAtBefore(String status, Instant now);

    boolean existsByGrantedToAndCaseIdAndStatusAndExpiresAtAfter(
            UUID grantedTo, UUID caseId, String status, Instant now);

    long countByGrantedToAndCreatedAtAfter(UUID grantedTo, Instant after);
}
