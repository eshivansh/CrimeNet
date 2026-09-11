package com.crimenet.assets;

import com.crimenet.audit.AuditService;
import com.crimenet.identity.AppUser;
import com.crimenet.identity.UserService;
import com.crimenet.policy.PolicyEvaluationService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PoliceAssetService {

    private final PoliceAssetRepository assetRepository;
    private final PolicyEvaluationService policyService;
    private final UserService userService;
    private final AuditService auditService;

    @Transactional
    public PoliceAsset registerAsset(RegisterAssetRequest request) {
        policyService.enforcePermission("ASSET", "MANAGE");
        AppUser currentUser = userService.getCurrentUser();

        if (assetRepository.findByAssetTag(request.assetTag()).isPresent()) {
            throw new IllegalArgumentException("Asset with tag '" + request.assetTag() + "' already exists");
        }

        PoliceAsset asset = PoliceAsset.builder()
                .assetTag(request.assetTag())
                .name(request.name())
                .category(request.category())
                .status("AVAILABLE")
                .department(request.department())
                .caseId(request.caseId())
                .orgId(currentUser.getOrgId())
                .metadata(request.metadata() != null ? request.metadata() : new HashMap<>())
                .createdBy(currentUser.getId())
                .build();

        asset = assetRepository.save(asset);

        auditService.record("ASSET_REGISTERED", currentUser.getId(), asset.getId(), asset.getCaseId(),
                "ASSET", Map.of(
                        "assetTag", asset.getAssetTag(),
                        "category", asset.getCategory(),
                        "name", asset.getName(),
                        "status", asset.getStatus()
                ));

        log.info("Registered police asset {} ({}) by {}", asset.getAssetTag(), asset.getCategory(), currentUser.getId());
        return asset;
    }

    @Transactional
    public PoliceAsset assignAsset(UUID assetId, AssignAssetRequest request) {
        policyService.enforcePermission("ASSET", "ASSIGN");
        AppUser currentUser = userService.getCurrentUser();

        PoliceAsset asset = assetRepository.findById(assetId)
                .orElseThrow(() -> new EntityNotFoundException("Asset not found: " + assetId));
        requireSameOrg(asset);

        if ("DECOMMISSIONED".equalsIgnoreCase(asset.getStatus())) {
            throw new IllegalStateException("Cannot assign a decommissioned asset");
        }

        String previousCustodian = asset.getCustodianBadge();
        asset.setCustodianId(request.custodianId());
        asset.setCustodianBadge(request.custodianBadge());
        asset.setCaseId(request.caseId());
        asset.setStatus("ISSUED");
        asset.setAssignedAt(Instant.now());

        asset = assetRepository.save(asset);

        auditService.record("ASSET_ASSIGNED", currentUser.getId(), asset.getId(), asset.getCaseId(),
                "ASSET", Map.of(
                        "assetTag", asset.getAssetTag(),
                        "custodianId", String.valueOf(request.custodianId()),
                        "custodianBadge", String.valueOf(request.custodianBadge()),
                        "caseId", String.valueOf(request.caseId()),
                        "previousCustodian", String.valueOf(previousCustodian)
                ));

        log.info("Asset {} assigned to officer {} ({})", asset.getAssetTag(), request.custodianBadge(), request.custodianId());
        return asset;
    }

    @Transactional
    public PoliceAsset returnAsset(UUID assetId, String notes) {
        policyService.enforcePermission("ASSET", "UPDATE");
        AppUser currentUser = userService.getCurrentUser();

        PoliceAsset asset = assetRepository.findById(assetId)
                .orElseThrow(() -> new EntityNotFoundException("Asset not found: " + assetId));
        requireSameOrg(asset);

        // ASSET.UPDATE is seeded for investigators, and this method cleared the custodian on
        // any asset id with no ownership check — so any investigator could return a firearm
        // recorded to a different officer.
        if (asset.getCustodianId() != null
                && !asset.getCustodianId().equals(currentUser.getId())
                && !policyService.hasRole("SUPERVISOR")
                && !policyService.hasRole("ADMIN")) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Only the recorded custodian or a supervisor may return this asset.");
        }

        String returnedBy = asset.getCustodianBadge();
        asset.setCustodianId(null);
        asset.setCustodianBadge(null);
        asset.setStatus("AVAILABLE");

        if (notes != null && !notes.isBlank()) {
            Map<String, Object> meta = asset.getMetadata() != null ? new HashMap<>(asset.getMetadata()) : new HashMap<>();
            meta.put("lastReturnNotes", notes);
            meta.put("returnedAt", Instant.now().toString());
            asset.setMetadata(meta);
        }

        asset = assetRepository.save(asset);

        auditService.record("ASSET_RETURNED", currentUser.getId(), asset.getId(), asset.getCaseId(),
                "ASSET", Map.of(
                        "assetTag", asset.getAssetTag(),
                        "previousCustodian", String.valueOf(returnedBy),
                        "notes", notes != null ? notes : ""
                ));

        log.info("Asset {} returned to inventory by {}", asset.getAssetTag(), currentUser.getId());
        return asset;
    }

    @Transactional
    public PoliceAsset updateStatus(UUID assetId, String status, String notes) {
        policyService.enforcePermission("ASSET", "UPDATE");
        AppUser currentUser = userService.getCurrentUser();

        PoliceAsset asset = assetRepository.findById(assetId)
                .orElseThrow(() -> new EntityNotFoundException("Asset not found: " + assetId));
        requireSameOrg(asset);

        String oldStatus = asset.getStatus();
        asset.setStatus(status.toUpperCase());

        if (notes != null && !notes.isBlank()) {
            Map<String, Object> meta = asset.getMetadata() != null ? new HashMap<>(asset.getMetadata()) : new HashMap<>();
            meta.put("statusChangeNotes", notes);
            meta.put("statusChangedAt", Instant.now().toString());
            asset.setMetadata(meta);
        }

        asset = assetRepository.save(asset);

        auditService.record("ASSET_STATUS_UPDATED", currentUser.getId(), asset.getId(), asset.getCaseId(),
                "ASSET", Map.of(
                        "assetTag", asset.getAssetTag(),
                        "oldStatus", oldStatus,
                        "newStatus", asset.getStatus(),
                        "notes", notes != null ? notes : ""
                ));

        log.info("Asset {} status changed from {} to {}", asset.getAssetTag(), oldStatus, asset.getStatus());
        return asset;
    }

    /**
     * Both read paths previously performed no permission check and no tenant scoping,
     * behind a controller that required only authentication.
     */
    @Transactional(readOnly = true)
    public PoliceAsset getAsset(UUID assetId) {
        policyService.enforcePermission("ASSET", "READ");
        PoliceAsset asset = assetRepository.findById(assetId)
                .orElseThrow(() -> new EntityNotFoundException("Asset not found: " + assetId));
        requireSameOrg(asset);
        return asset;
    }

    @Transactional(readOnly = true)
    public List<PoliceAsset> listAssets(String category, String status, UUID caseId, UUID custodianId) {
        policyService.enforcePermission("ASSET", "READ");
        return assetRepository.searchAssets(
                userService.getCurrentUser().getOrgId(), category, status, caseId, custodianId);
    }

    /** An asset belonging to another agency is not visible, whatever the caller's role. */
    private void requireSameOrg(PoliceAsset asset) {
        UUID callerOrg = userService.getCurrentUser().getOrgId();
        if (asset.getOrgId() != null && !asset.getOrgId().equals(callerOrg)) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "This asset belongs to another organization.");
        }
    }

    public record RegisterAssetRequest(
            String assetTag,
            String name,
            String category,
            String department,
            UUID caseId,
            Map<String, Object> metadata
    ) {}

    public record AssignAssetRequest(
            UUID custodianId,
            String custodianBadge,
            UUID caseId
    ) {}
}
