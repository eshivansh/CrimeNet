package com.crimenet.integrations;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ExternalReferenceRepository extends JpaRepository<ExternalReference, UUID> {
    Optional<ExternalReference> findBySourceSystemAndExternalId(String sourceSystem, String externalId);
    List<ExternalReference> findByLocalResourceId(UUID localResourceId);
}
