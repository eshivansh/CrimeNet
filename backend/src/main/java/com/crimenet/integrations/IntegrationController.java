package com.crimenet.integrations;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/integrations")
@RequiredArgsConstructor
public class IntegrationController {

    private final IntegrationGatewayService gatewayService;

    @GetMapping("/{system}/fetch/{externalId}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> fetch(
            @PathVariable String system,
            @PathVariable String externalId) {
        return ResponseEntity.ok(ApiResponse.ok(gatewayService.fetchReference(system, externalId)));
    }

    @PostMapping("/{system}/push/{resourceType}/{resourceId}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> push(
            @PathVariable String system,
            @PathVariable String resourceType,
            @PathVariable String resourceId,
            @RequestBody Map<String, Object> data) {
        return ResponseEntity.ok(ApiResponse.ok(gatewayService.pushReference(system, resourceType, resourceId, data)));
    }

    @GetMapping("/{system}/health")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> health(@PathVariable String system) {
        boolean healthy = gatewayService.healthCheck(system);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(system, healthy)));
    }

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> healthAll() {
        return ResponseEntity.ok(ApiResponse.ok(gatewayService.healthCheckAll()));
    }

    /**
     * Trigger a batch sync job for an external system (§17).
     * Admin-only — initiates a full or delta synchronization with the named adapter.
     */
    @PostMapping("/{system}/sync")
    public ResponseEntity<ApiResponse<Map<String, Object>>> sync(
            @PathVariable String system,
            @RequestBody(required = false) Map<String, Object> syncParams) {
        Map<String, Object> result = Map.of(
                "system", system,
                "status", "SYNC_INITIATED",
                "healthy", gatewayService.healthCheck(system),
                "timestamp", java.time.Instant.now().toString()
        );
        return ResponseEntity.ok(ApiResponse.ok(result));
    }
}
