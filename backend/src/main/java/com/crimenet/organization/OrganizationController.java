package com.crimenet.organization;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/organizations")
@RequiredArgsConstructor
public class OrganizationController {

    private final OrganizationService organizationService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<Organization>>> list() {
        return ResponseEntity.ok(ApiResponse.ok(organizationService.listOrganizations()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Organization>> get(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(organizationService.getOrganization(id)));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<Organization>> create(@RequestBody CreateOrganizationRequest request) {
        Organization org = organizationService.createOrganization(request.name(), request.code());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(org));
    }

    @GetMapping("/{id}/departments")
    public ResponseEntity<ApiResponse<List<Department>>> listDepartments(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(organizationService.listDepartments(id)));
    }

    @PostMapping("/{id}/departments")
    public ResponseEntity<ApiResponse<Department>> createDepartment(
            @PathVariable UUID id,
            @RequestBody CreateDepartmentRequest request) {
        Department dept = organizationService.createDepartment(id, request.name(), request.code());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(dept));
    }

    public record CreateOrganizationRequest(String name, String code) {}
    public record CreateDepartmentRequest(String name, String code) {}
}
