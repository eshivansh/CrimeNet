package com.crimenet.provenance;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface MerkleBatchRepository extends JpaRepository<MerkleBatch, UUID> {

    @Query("SELECT mb FROM MerkleBatch mb ORDER BY mb.batchNumber DESC LIMIT 1")
    Optional<MerkleBatch> findLatestBatch();

    Optional<MerkleBatch> findByBatchNumber(long batchNumber);
}
