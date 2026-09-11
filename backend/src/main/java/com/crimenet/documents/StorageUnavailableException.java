package com.crimenet.documents;

/**
 * Object storage could not be reached or did not complete the operation.
 *
 * <p>Separated from integrity failures on purpose: {@code verifyIntegrity} used to catch
 * every exception and return {@code valid=false}, so a MinIO restart made every document in
 * the system look tampered. A storage outage says nothing about a document's integrity, and
 * the two must not be reported the same way. Maps to 503.
 */
public class StorageUnavailableException extends RuntimeException {

    public StorageUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public StorageUnavailableException(String message) {
        super(message);
    }
}
