package com.crimenet.sharing;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SharePackageRepository extends JpaRepository<SharePackage, UUID> {
    List<SharePackage> findByCaseIdAndStatus(UUID caseId, String status);
    List<SharePackage> findByRecipientIdAndStatus(UUID recipientId, String status);
}
