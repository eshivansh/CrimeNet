package com.crimenet.assets;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/assets")
@RequiredArgsConstructor
@Tag(name = "Police Assets", description = "Lifecycle tracking for weapons, bodycams, vehicles, and investigation kits")
public class PoliceAssetController {

    private final PoliceAssetService assetService;

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    @Operation(summary = "Register a new police asset into inventory")
    public ResponseEntity<PoliceAsset> registerAsset(@Valid @RequestBody PoliceAssetService.RegisterAssetRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(assetService.registerAsset(request));
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Search and list police assets by category, status, case or custodian")
    public ResponseEntity<List<PoliceAsset>> listAssets(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) UUID caseId,
            @RequestParam(required = false) UUID custodianId) {
        return ResponseEntity.ok(assetService.listAssets(category, status, caseId, custodianId));
    }

    @GetMapping("/{assetId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get police asset details by ID")
    public ResponseEntity<PoliceAsset> getAsset(@PathVariable UUID assetId) {
        return ResponseEntity.ok(assetService.getAsset(assetId));
    }

    @PostMapping("/{assetId}/assign")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    @Operation(summary = "Assign a police asset to an officer or case")
    public ResponseEntity<PoliceAsset> assignAsset(
            @PathVariable UUID assetId,
            @Valid @RequestBody PoliceAssetService.AssignAssetRequest request) {
        return ResponseEntity.ok(assetService.assignAsset(assetId, request));
    }

    @PostMapping("/{assetId}/return")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR', 'INVESTIGATOR')")
    @Operation(summary = "Return an issued asset to inventory")
    public ResponseEntity<PoliceAsset> returnAsset(
            @PathVariable UUID assetId,
            @RequestParam(required = false) String notes) {
        return ResponseEntity.ok(assetService.returnAsset(assetId, notes));
    }

    @PatchMapping("/{assetId}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    @Operation(summary = "Update asset condition or operational status")
    public ResponseEntity<PoliceAsset> updateStatus(
            @PathVariable UUID assetId,
            @RequestParam String status,
            @RequestParam(required = false) String notes) {
        return ResponseEntity.ok(assetService.updateStatus(assetId, status, notes));
    }
}
