package com.crimenet.common;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * Allocates the counters behind court-facing business identifiers.
 *
 * <p>These identifiers previously came from {@code repository.count() + 1}, which
 * raced two concurrent creates onto the same number — one of them then died on the
 * unique constraint — and reissued a number whenever a transaction rolled back.
 * Two exhibits sharing one court identifier is directly disputable in evidence.
 *
 * <p>A PostgreSQL sequence is atomic, gap-tolerant by design, and unaffected by
 * rollback, which is exactly the semantic a permanent identifier needs.
 */
@Slf4j
@Service
public class IdentifierSequenceService {

    /** Sequences created in V13. The allowlist keeps the name out of reach of any caller. */
    private static final Set<String> KNOWN_SEQUENCES =
            Set.of("case_number_seq", "evidence_code_seq", "document_business_seq");

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * @param sequenceName one of the sequences created in V13
     * @return the next value, allocated atomically
     */
    public long next(String sequenceName) {
        if (!KNOWN_SEQUENCES.contains(sequenceName)) {
            throw new IllegalArgumentException("Unknown identifier sequence: " + sequenceName);
        }
        // Safe to interpolate: the name is constrained to the allowlist above, and
        // PostgreSQL will not accept a sequence name as a bind parameter.
        Object value = entityManager
                .createNativeQuery("SELECT nextval('" + sequenceName + "')")
                .getSingleResult();
        return ((Number) value).longValue();
    }
}
