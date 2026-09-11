package com.crimenet.infrastructure;

import io.minio.BucketExistsArgs;
import io.minio.MinioClient;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Readiness signal for object storage.
 *
 * <p>Boot auto-configures indicators for Redis, RabbitMQ and the datasource, but nothing
 * reported on MinIO — where every document and evidence artifact actually lives. The
 * instance could be healthy with no buckets and every upload failing at request time.
 *
 * <p>The bean name is what names the contributor, so this class must stay {@code minio}
 * to match the readiness group in application.yml.
 */
@Component("minio")
@RequiredArgsConstructor
public class MinioHealthIndicator implements HealthIndicator {

    private final MinioClient minioClient;

    @Value("${minio.buckets.documents}")
    private String documentsBucket;

    @Value("${minio.endpoint}")
    private String endpoint;

    @Override
    public Health health() {
        try {
            boolean exists = minioClient.bucketExists(
                    BucketExistsArgs.builder().bucket(documentsBucket).build());

            if (!exists) {
                // Reachable but unusable: uploads would fail on every request.
                return Health.down()
                        .withDetail("endpoint", endpoint)
                        .withDetail("bucket", documentsBucket)
                        .withDetail("reason", "The documents bucket does not exist")
                        .build();
            }

            return Health.up()
                    .withDetail("endpoint", endpoint)
                    .withDetail("bucket", documentsBucket)
                    .build();

        } catch (Exception e) {
            return Health.down()
                    .withDetail("endpoint", endpoint)
                    .withDetail("error", e.getClass().getSimpleName() + ": " + e.getMessage())
                    .build();
        }
    }
}
