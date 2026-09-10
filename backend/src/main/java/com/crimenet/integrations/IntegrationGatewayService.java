package com.crimenet.integrations;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Integration gateway routing calls to the appropriate adapter by system name (§16).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IntegrationGatewayService {

    private final List<ExternalSystemAdapter> adapters;

    private Map<String, ExternalSystemAdapter> adapterMap;

    private Map<String, ExternalSystemAdapter> getAdapterMap() {
        if (adapterMap == null) {
            adapterMap = adapters.stream()
                    .collect(Collectors.toMap(ExternalSystemAdapter::getSystemName, Function.identity()));
        }
        return adapterMap;
    }

    private final com.crimenet.integrations.ExternalReferenceRepository externalReferenceRepository;
    private final com.crimenet.integrations.SyncJobRepository syncJobRepository;

    public Map<String, Object> fetchReference(String systemName, String externalId) {
        ExternalSystemAdapter adapter = getAdapter(systemName);
        log.info("Integration fetch: {} / {}", systemName, externalId);
        return adapter.fetchReference(externalId);
    }

    public Map<String, Object> pushReference(String systemName, String resourceType,
                                              String resourceId, Map<String, Object> data) {
        ExternalSystemAdapter adapter = getAdapter(systemName);
        log.info("Integration push: {} / {} / {}", systemName, resourceType, resourceId);
        Map<String, Object> response = adapter.pushReference(resourceType, resourceId, data);
        
        // Track the external reference locally
        if (response != null && response.containsKey("externalId")) {
            String externalId = response.get("externalId").toString();
            com.crimenet.integrations.ExternalReference ref = com.crimenet.integrations.ExternalReference.builder()
                    .sourceSystem(systemName.toUpperCase())
                    .externalId(externalId)
                    .resourceType(resourceType)
                    .localResourceId(java.util.UUID.fromString(resourceId))
                    .syncStatus("SYNCED")
                    .build();
            externalReferenceRepository.save(ref);
        }
        
        return response;
    }

    public boolean healthCheck(String systemName) {
        ExternalSystemAdapter adapter = getAdapter(systemName);
        return adapter.healthCheck();
    }

    public Map<String, Boolean> healthCheckAll() {
        return getAdapterMap().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> {
                            try { return e.getValue().healthCheck(); }
                            catch (Exception ex) { return false; }
                        }
                ));
    }

    private ExternalSystemAdapter getAdapter(String systemName) {
        ExternalSystemAdapter adapter = getAdapterMap().get(systemName.toUpperCase());
        if (adapter == null) {
            throw new IllegalArgumentException("Unknown integration system: " + systemName);
        }
        return adapter;
    }
}
