package com.crimenet.sharing;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ShareAccessRepository extends JpaRepository<ShareAccess, UUID> {
    List<ShareAccess> findBySharePackageIdOrderByAccessedAtDesc(UUID sharePackageId);
}
