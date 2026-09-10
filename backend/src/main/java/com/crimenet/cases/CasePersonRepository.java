package com.crimenet.cases;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface CasePersonRepository extends JpaRepository<CasePerson, UUID> {
    List<CasePerson> findByCaseIdAndStatus(UUID caseId, String status);
    List<CasePerson> findByCaseId(UUID caseId);
}
