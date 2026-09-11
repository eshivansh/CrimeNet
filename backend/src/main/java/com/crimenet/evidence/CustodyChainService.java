package com.crimenet.evidence;

import com.crimenet.documents.HashService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Canonical hashing and verification for the chain of custody.
 *
 * <p>Two defects this exists to close. The event hash covered five fields out of eleven, so
 * {@code purpose}, {@code location}, {@code notes}, {@code signature} and the timestamp could
 * be rewritten with the chain still validating perfectly — and the recorded location of a
 * seizure is precisely the sort of thing a §65B certificate asserts. And nothing in the
 * codebase ever recomputed a hash or walked the linkage, so the tamper-evident structure
 * produced no evidence that anyone could read.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustodyChainService {

    private final CustodyEventRepository custodyEventRepository;
    private final HashService hashService;

    /**
     * Field-tagged canonical form of a custody event, covering every persisted field.
     *
     * <p>Tagged and delimited rather than concatenated, so no two different field splits can
     * produce the same string.
     */
    public String canonicalForm(CustodyEvent event) {
        return new StringBuilder()
                .append("v2|")
                .append("evidence=").append(nullSafe(event.getEvidenceId())).append('|')
                .append("action=").append(nullSafe(event.getAction())).append('|')
                .append("from=").append(nullSafe(event.getFromActor())).append('|')
                .append("to=").append(nullSafe(event.getToActor())).append('|')
                .append("purpose=").append(nullSafe(event.getPurpose())).append('|')
                .append("location=").append(nullSafe(event.getLocation())).append('|')
                .append("notes=").append(nullSafe(event.getNotes())).append('|')
                .append("artifact=").append(nullSafe(event.getArtifactId())).append('|')
                .append("signature=").append(nullSafe(event.getSignature())).append('|')
                .append("prevEvent=").append(nullSafe(event.getPreviousEventId())).append('|')
                .append("at=").append(storedPrecision(event.getCreatedAt()))
                .toString();
    }

    /**
     * The timestamp exactly as PostgreSQL will return it.
     *
     * <p>TIMESTAMPTZ keeps microseconds; Instant.now() on this JDK carries sub-microsecond
     * digits. Hashing the in-memory value meant every event failed its own verification
     * the moment it was read back. The canonical form uses the stored precision, so the
     * value that is hashed is the value that can be recomputed.
     */
    static String storedPrecision(Instant instant) {
        return instant == null ? "" : instant.truncatedTo(java.time.temporal.ChronoUnit.MICROS).toString();
    }

    public String computeEventHash(CustodyEvent event, String previousEventHash) {
        return hashService.computeChainedHash(previousEventHash, canonicalForm(event));
    }

    /**
     * The chain in linkage order.
     *
     * <p>Ordering by {@code created_at} alone is not a total order — the timestamp comes from
     * the JVM, so ties resolve nondeterministically and the "current head" used for the
     * optimistic-lock check could be the wrong event. Walking {@code previousEventId} gives
     * the order the chain actually asserts; timestamp order is the fallback when the linkage
     * is broken.
     */
    @Transactional(readOnly = true)
    public List<CustodyEvent> orderedChain(UUID evidenceId) {
        List<CustodyEvent> events = custodyEventRepository.findByEvidenceIdOrderByCreatedAtAsc(evidenceId);
        if (events.size() <= 1) {
            return events;
        }

        Map<UUID, CustodyEvent> byPrevious = new HashMap<>();
        CustodyEvent root = null;
        for (CustodyEvent event : events) {
            if (event.getPreviousEventId() == null) {
                root = event;
            } else {
                byPrevious.put(event.getPreviousEventId(), event);
            }
        }

        if (root == null) {
            log.warn("CUSTODY_CHAIN_NO_ROOT: evidence {} has no origin event; falling back to timestamp order",
                    evidenceId);
            return events;
        }

        List<CustodyEvent> ordered = new ArrayList<>(events.size());
        CustodyEvent cursor = root;
        while (cursor != null && ordered.size() <= events.size()) {
            ordered.add(cursor);
            cursor = byPrevious.get(cursor.getId());
        }

        if (ordered.size() != events.size()) {
            log.warn("CUSTODY_CHAIN_INCOMPLETE: evidence {} walks {} of {} events; the chain is "
                    + "forked or broken", evidenceId, ordered.size(), events.size());
            return events;
        }
        return ordered;
    }

    /**
     * Walk the chain, recompute every hash, and check every link.
     */
    @Transactional(readOnly = true)
    public CustodyChainVerification verify(UUID evidenceId) {
        List<CustodyEvent> chain = orderedChain(evidenceId);
        List<LinkVerdict> verdicts = new ArrayList<>(chain.size());
        boolean intact = true;

        String expectedPreviousHash = null;
        UUID expectedPreviousId = null;

        for (int i = 0; i < chain.size(); i++) {
            CustodyEvent event = chain.get(i);
            List<String> problems = new ArrayList<>();

            String recomputed = computeEventHash(event, event.getPreviousEventHash());
            boolean hashMatches = recomputed.equals(event.getEventHash());
            boolean legacy = false;

            if (!hashMatches) {
                // Events written before the hash covered every field are recognised as
                // legacy rather than reported as tampering: intact, but less protected.
                if (legacyHash(event).equals(event.getEventHash())) {
                    legacy = true;
                } else {
                    problems.add("event_hash does not match the event's own fields");
                    intact = false;
                }
            }

            if (i > 0) {
                if (!Objects.equals(expectedPreviousId, event.getPreviousEventId())) {
                    problems.add("previous_event_id does not point at the preceding event");
                    intact = false;
                }
                if (!Objects.equals(expectedPreviousHash, event.getPreviousEventHash())) {
                    problems.add("previous_event_hash does not match the preceding event's hash");
                    intact = false;
                }
            } else if (event.getPreviousEventId() != null) {
                problems.add("The first event in the chain references a predecessor");
                intact = false;
            }

            verdicts.add(new LinkVerdict(
                    event.getId(), event.getAction(), event.getCreatedAt(),
                    problems.isEmpty(), legacy, problems));

            expectedPreviousHash = event.getEventHash();
            expectedPreviousId = event.getId();
        }

        if (!intact) {
            log.error("CUSTODY_CHAIN_BROKEN: evidence {} failed verification", evidenceId);
        }
        return new CustodyChainVerification(evidenceId, chain.size(), intact, verdicts);
    }

    /** The original five-field construction, retained only to classify pre-fix events. */
    private String legacyHash(CustodyEvent event) {
        if (event.getPreviousEventId() == null) {
            String payload = "{\"action\":\"" + event.getAction()
                    + "\",\"evidenceId\":\"" + event.getEvidenceId()
                    + "\",\"toActor\":\"" + event.getToActor() + "\"}";
            return hashService.computeChainedHash(null, payload);
        }
        String payload = "{\"action\":\"" + event.getAction()
                + "\",\"evidenceId\":\"" + event.getEvidenceId()
                + "\",\"fromActor\":\"" + event.getFromActor()
                + "\",\"previousEventId\":\"" + event.getPreviousEventId()
                + "\",\"toActor\":\"" + event.getToActor() + "\"}";
        return hashService.computeChainedHash(event.getPreviousEventHash(), payload);
    }

    private String nullSafe(Object value) {
        return value == null ? "" : value.toString();
    }

    /**
     * @param legacy true when the link verifies under the v1 hash, which covers action,
     *               evidence, actors and previous id only — purpose, location, notes and
     *               signature are not protected on that event.
     */
    public record LinkVerdict(
            UUID eventId,
            String action,
            Instant occurredAt,
            boolean valid,
            boolean legacy,
            List<String> problems
    ) {}

    public record CustodyChainVerification(
            UUID evidenceId,
            int linksChecked,
            boolean intact,
            List<LinkVerdict> links
    ) {}
}
