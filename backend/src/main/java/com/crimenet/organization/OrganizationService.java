package com.crimenet.organization;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class OrganizationService {

    private final OrganizationRepository organizationRepository;
    private final DepartmentRepository departmentRepository;

    public List<Organization> listOrganizations() {
        return organizationRepository.findAll();
    }

    public Organization getOrganization(UUID id) {
        return organizationRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Organization not found: " + id));
    }

    public Organization getOrganizationByCode(String code) {
        return organizationRepository.findByCode(code)
                .orElseThrow(() -> new EntityNotFoundException("Organization not found: " + code));
    }

    @Transactional
    public Organization createOrganization(String name, String code) {
        if (organizationRepository.existsByCode(code)) {
            throw new IllegalArgumentException("Organization code already exists: " + code);
        }
        Organization org = Organization.builder().name(name).code(code).build();
        log.info("Creating organization: {} ({})", name, code);
        return organizationRepository.save(org);
    }

    public List<Department> listDepartments(UUID orgId) {
        return departmentRepository.findByOrgId(orgId);
    }

    @Transactional
    public Department createDepartment(UUID orgId, String name, String code) {
        // Verify org exists
        getOrganization(orgId);
        Department dept = Department.builder().orgId(orgId).name(name).code(code).build();
        log.info("Creating department: {} ({}) in org {}", name, code, orgId);
        return departmentRepository.save(dept);
    }
}
