package com.crimenet.infrastructure;

import io.minio.*;
import io.minio.messages.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

/**
 * MinIO storage operations — upload, download, and pre-signed URL generation.
 * All bucket access is through this service; no raw MinIO credentials reach the frontend.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MinioStorageService {

    private final MinioClient minioClient;

    @Value("${minio.buckets.documents}")
    private String documentsBucket;

    @Value("${minio.buckets.evidence}")
    private String evidenceBucket;

    @Value("${minio.buckets.quarantine}")
    private String quarantineBucket;

    @Value("${minio.buckets.archive:crimenet-archive}")
    private String archiveBucket;

    @Value("${minio.buckets.court-packages:crimenet-court-packages}")
    private String courtPackagesBucket;

    @Value("${minio.sse-enabled:false}")
    private boolean sseEnabled;

    @jakarta.annotation.PostConstruct
    public void configureBuckets() {
        try {
            // Configure 1-day quarantine lifecycle
            LifecycleRule expireQuarantine = new LifecycleRule(
                    Status.ENABLED,
                    null,
                    new Expiration((ZonedDateTime) null, 1, null),
                    new RuleFilter(""),
                    "expire-quarantine",
                    null,
                    null,
                    null);
            minioClient.setBucketLifecycle(SetBucketLifecycleArgs.builder()
                    .bucket(quarantineBucket)
                    .config(new LifecycleConfiguration(List.of(expireQuarantine)))
                    .build());
            log.info("Configured 1-day lifecycle rule for quarantine bucket");
        } catch (Exception e) {
            log.warn("Failed to configure MinIO lifecycle rules: {}", e.getMessage());
        }
    }

    /**
     * Server-side encryption for object writes.
     *
     * <p>SSE-S3 requires the MinIO server to be backed by a KMS (KES). A plain MinIO
     * container has no KMS, and every upload would be rejected with
     * "Server side encryption specified but KMS is not configured". So SSE is opt-in:
     * enable {@code minio.sse-enabled} only once a KMS-backed MinIO is in place.
     * Returning {@code null} leaves the write unencrypted; MinIO treats a null SSE as absent.
     */
    private ServerSideEncryption getSse() {
        return sseEnabled ? new ServerSideEncryptionS3() : null;
    }

    /**
     * Upload a document to the documents bucket.
     */
    public void uploadDocument(String objectKey, byte[] content, String contentType) {
        try {
            minioClient.putObject(PutObjectArgs.builder()
                    .bucket(documentsBucket)
                    .object(objectKey)
                    .stream(new ByteArrayInputStream(content), content.length, -1)
                    .contentType(contentType)
                    .sse(getSse())
                    .build());
            log.debug("Uploaded to {}/{}", documentsBucket, objectKey);
        } catch (Exception e) {
            log.error("Failed to upload to MinIO: {}/{}", documentsBucket, objectKey, e);
            throw new RuntimeException("MinIO upload failed", e);
        }
    }

    /**
     * Download a document from the documents bucket.
     */
    public byte[] downloadDocument(String objectKey) {
        // try-with-resources: GetObjectResponse wraps a live HTTP connection, and leaving
        // it unclosed leaked one OkHttp connection per download.
        try (GetObjectResponse response = minioClient.getObject(GetObjectArgs.builder()
                .bucket(documentsBucket)
                .object(objectKey)
                .build())) {
            return response.readAllBytes();
        } catch (Exception e) {
            log.error("Failed to download from MinIO: {}/{}", documentsBucket, objectKey, e);
            throw new RuntimeException("MinIO download failed", e);
        }
    }

    /**
     * Upload evidence artifact to the evidence bucket.
     */
    public void uploadEvidence(String objectKey, byte[] content, String contentType) {
        try {
            minioClient.putObject(PutObjectArgs.builder()
                    .bucket(evidenceBucket)
                    .object(objectKey)
                    .stream(new ByteArrayInputStream(content), content.length, -1)
                    .contentType(contentType)
                    .sse(getSse())
                    .build());
            log.debug("Uploaded to {}/{}", evidenceBucket, objectKey);
        } catch (Exception e) {
            log.error("Failed to upload to MinIO: {}/{}", evidenceBucket, objectKey, e);
            throw new RuntimeException("MinIO evidence upload failed", e);
        }
    }

    /**
     * Upload an unscanned document to the quarantine bucket.
     */
    public void uploadToQuarantine(String objectKey, byte[] content, String contentType) {
        try {
            minioClient.putObject(PutObjectArgs.builder()
                    .bucket(quarantineBucket)
                    .object(objectKey)
                    .stream(new ByteArrayInputStream(content), content.length, -1)
                    .contentType(contentType)
                    .sse(getSse())
                    .build());
            log.debug("Uploaded to {}/{}", quarantineBucket, objectKey);
        } catch (Exception e) {
            log.error("Failed to upload to quarantine: {}/{}", quarantineBucket, objectKey, e);
            throw new RuntimeException("MinIO quarantine upload failed", e);
        }
    }

    /**
     * Move an evidence artifact from quarantine to the final evidence bucket using server-side copy.
     */
    public void moveToEvidence(String sourceObjectKey, String targetObjectKey) {
        try {
            minioClient.copyObject(CopyObjectArgs.builder()
                    .bucket(evidenceBucket)
                    .object(targetObjectKey)
                    .source(CopySource.builder()
                            .bucket(quarantineBucket)
                            .object(sourceObjectKey)
                            .build())
                    .sse(getSse())
                    .build());
            log.debug("Copied {}/{} to {}/{}", quarantineBucket, sourceObjectKey, evidenceBucket, targetObjectKey);
        } catch (Exception e) {
            log.error("Failed to copy from quarantine to evidence: {}", e.getMessage(), e);
            throw new RuntimeException("MinIO copy to evidence failed", e);
        }
    }

    /**
     * Move a document from quarantine to the final documents bucket using server-side copy.
     */
    public void moveToDocuments(String sourceObjectKey, String targetObjectKey) {
        try {
            minioClient.copyObject(CopyObjectArgs.builder()
                    .bucket(documentsBucket)
                    .object(targetObjectKey)
                    .source(CopySource.builder()
                            .bucket(quarantineBucket)
                            .object(sourceObjectKey)
                            .build())
                    .sse(getSse())
                    .build());
            log.debug("Copied {}/{} to {}/{}", quarantineBucket, sourceObjectKey, documentsBucket, targetObjectKey);
        } catch (Exception e) {
            log.error("Failed to copy from quarantine to documents: {}", e.getMessage(), e);
            throw new RuntimeException("MinIO copy failed", e);
        }
    }

    /**
     * Delete an object from the quarantine bucket.
     */
    public void deleteFromQuarantine(String objectKey) {
        try {
            minioClient.removeObject(RemoveObjectArgs.builder()
                    .bucket(quarantineBucket)
                    .object(objectKey)
                    .build());
            log.debug("Deleted {}/{}", quarantineBucket, objectKey);
        } catch (Exception e) {
            log.error("Failed to delete from quarantine: {}/{}", quarantineBucket, objectKey, e);
            // Non-fatal, lifecycle rules will eventually clean it up
        }
    }

    /**
     * Generate a pre-signed URL for secure, time-bound download.
     */
    public String generatePresignedUrl(String bucketName, String objectKey, int expirySeconds) {
        return generatePresignedUrl(bucketName, objectKey, expirySeconds, null);
    }

    /**
     * Generate a pre-signed URL for secure, time-bound download.
     *
     * <p>The object is served straight off the storage origin, which does not pass
     * through the application's security headers. The response overrides below force the
     * browser to save rather than render: without them, an object whose stored content
     * type came from the client's own multipart header renders inline on the MinIO origin.
     *
     * @param downloadFilename suggested filename, or null to serve as a generic download
     */
    public String generatePresignedUrl(String bucketName, String objectKey, int expirySeconds,
                                       String downloadFilename) {
        try {
            String disposition = "attachment";
            if (downloadFilename != null && !downloadFilename.isBlank()) {
                String safe = downloadFilename.replaceAll("[^a-zA-Z0-9._\\-]", "_");
                disposition = "attachment; filename=\"" + safe + "\"";
            }

            Map<String, String> responseHeaders = new java.util.HashMap<>();
            responseHeaders.put("response-content-disposition", disposition);
            responseHeaders.put("response-content-type", "application/octet-stream");

            return minioClient.getPresignedObjectUrl(GetPresignedObjectUrlArgs.builder()
                    .method(io.minio.http.Method.GET)
                    .bucket(bucketName)
                    .object(objectKey)
                    .expiry(expirySeconds, java.util.concurrent.TimeUnit.SECONDS)
                    .extraQueryParams(responseHeaders)
                    .build());
        } catch (Exception e) {
            log.error("Failed to generate presigned URL for {}/{}: {}", bucketName, objectKey, e.getMessage());
            throw new RuntimeException("Failed to generate download link", e);
        }
    }

    /**
     * Move a document to the archive bucket.
     */
    public void moveToArchive(String sourceBucket, String sourceObjectKey, String targetObjectKey) {
        try {
            // Copy to archive
            minioClient.copyObject(CopyObjectArgs.builder()
                    .bucket(archiveBucket)
                    .object(targetObjectKey)
                    .source(CopySource.builder()
                            .bucket(sourceBucket)
                            .object(sourceObjectKey)
                            .build())
                    .sse(getSse())
                    .build());
            
            // Delete from source
            minioClient.removeObject(RemoveObjectArgs.builder()
                    .bucket(sourceBucket)
                    .object(sourceObjectKey)
                    .build());
            log.info("Archived object {} from {} to {}", sourceObjectKey, sourceBucket, archiveBucket);
        } catch (Exception e) {
            log.error("Failed to archive object: {}", e.getMessage(), e);
            throw new RuntimeException("MinIO archival failed", e);
        }
    }
}
