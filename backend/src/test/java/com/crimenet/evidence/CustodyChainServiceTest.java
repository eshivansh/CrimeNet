package com.crimenet.evidence;

import com.crimenet.documents.HashService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The custody chain is the evidentiary spine of the system, and it had two defects: the
 * hash covered five of eleven persisted fields, and nothing ever verified the chain at all.
 */
class CustodyChainServiceTest {

    private CustodyEventRepository repository;
    private CustodyChainService chain;

    private final UUID evidenceId = UUID.randomUUID();
    private final UUID officerA = UUID.randomUUID();
    private final UUID officerB = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        repository = Mockito.mock(CustodyEventRepository.class);
        chain = new CustodyChainService(repository, new HashService());
    }

    @Test
    @DisplayName("the hash covers location, purpose, notes and signature")
    void hashCoversEveryPersistedField() {
        // These four were persisted but unhashed, so the recorded location of a seizure
        // could be rewritten and the chain still validated perfectly.
        CustodyEvent event = transfer("Seized at 14 MG Road, Kanpur", "Forensic analysis", "Sealed bag 4", "sig-a");
        String original = chain.computeEventHash(event, null);

        event.setLocation("Seized at 22 Station Road, Agra");
        assertThat(chain.computeEventHash(event, null))
                .as("rewriting the seizure location must change the hash")
                .isNotEqualTo(original);

        event.setLocation("Seized at 14 MG Road, Kanpur");
        event.setPurpose("Disposal");
        assertThat(chain.computeEventHash(event, null)).isNotEqualTo(original);

        event.setPurpose("Forensic analysis");
        event.setNotes("Bag reopened");
        assertThat(chain.computeEventHash(event, null)).isNotEqualTo(original);

        event.setNotes("Sealed bag 4");
        event.setSignature("sig-forged");
        assertThat(chain.computeEventHash(event, null)).isNotEqualTo(original);
    }

    @Test
    @DisplayName("an intact chain verifies")
    void intactChainVerifies() {
        List<CustodyEvent> events = buildChain();
        Mockito.when(repository.findByEvidenceIdOrderByCreatedAtAsc(evidenceId)).thenReturn(events);

        CustodyChainService.CustodyChainVerification result = chain.verify(evidenceId);

        assertThat(result.intact()).isTrue();
        assertThat(result.linksChecked()).isEqualTo(2);
        assertThat(result.links()).allMatch(CustodyChainService.LinkVerdict::valid);
    }

    @Test
    @DisplayName("rewriting a field after the fact breaks verification")
    void detectsFieldTampering() {
        List<CustodyEvent> events = buildChain();
        events.get(1).setLocation("Somewhere else entirely");
        Mockito.when(repository.findByEvidenceIdOrderByCreatedAtAsc(evidenceId)).thenReturn(events);

        CustodyChainService.CustodyChainVerification result = chain.verify(evidenceId);

        assertThat(result.intact()).isFalse();
        assertThat(result.links().get(1).problems()).isNotEmpty();
    }

    @Test
    @DisplayName("a broken link is reported")
    void detectsBrokenLinkage() {
        List<CustodyEvent> events = buildChain();
        events.get(1).setPreviousEventHash("00".repeat(32));
        Mockito.when(repository.findByEvidenceIdOrderByCreatedAtAsc(evidenceId)).thenReturn(events);

        CustodyChainService.CustodyChainVerification result = chain.verify(evidenceId);

        assertThat(result.intact()).isFalse();
    }

    @Test
    @DisplayName("the chain is walked by linkage, not by timestamp")
    void ordersByLinkageNotTimestamp() {
        // createdAt comes from the JVM, so ties resolve nondeterministically and the
        // "current head" used for the optimistic-lock check could be the wrong event.
        List<CustodyEvent> events = buildChain();
        Instant tie = Instant.parse("2026-03-01T10:00:00Z");
        events.get(0).setCreatedAt(tie);
        events.get(1).setCreatedAt(tie);
        // Re-hash so the chain is genuinely intact at these timestamps.
        events.get(0).setEventHash(chain.computeEventHash(events.get(0), null));
        events.get(1).setPreviousEventHash(events.get(0).getEventHash());
        events.get(1).setEventHash(chain.computeEventHash(events.get(1), events.get(0).getEventHash()));

        Mockito.when(repository.findByEvidenceIdOrderByCreatedAtAsc(evidenceId))
                .thenReturn(List.of(events.get(1), events.get(0))); // deliberately wrong order

        List<CustodyEvent> ordered = chain.orderedChain(evidenceId);

        assertThat(ordered.get(0).getId()).isEqualTo(events.get(0).getId());
        assertThat(ordered.get(1).getId()).isEqualTo(events.get(1).getId());
    }

    // ── helpers ──

    private List<CustodyEvent> buildChain() {
        CustodyEvent registered = CustodyEvent.builder()
                .evidenceId(evidenceId)
                .toActor(officerA)
                .action("REGISTERED")
                .purpose("Initial evidence registration")
                .location("Seized at 14 MG Road, Kanpur")
                .build();
        registered.setId(UUID.randomUUID());
        registered.setCreatedAt(Instant.parse("2026-03-01T10:00:00Z"));
        registered.setEventHash(chain.computeEventHash(registered, null));

        CustodyEvent handover = CustodyEvent.builder()
                .evidenceId(evidenceId)
                .fromActor(officerA)
                .toActor(officerB)
                .action("TRANSFERRED")
                .purpose("Forensic analysis")
                .location("Forensic Science Laboratory, Lucknow")
                .notes("Sealed bag 4, tamper strip intact")
                .previousEventId(registered.getId())
                .previousEventHash(registered.getEventHash())
                .build();
        handover.setId(UUID.randomUUID());
        handover.setCreatedAt(Instant.parse("2026-03-02T09:30:00Z"));
        handover.setEventHash(chain.computeEventHash(handover, registered.getEventHash()));

        return new java.util.ArrayList<>(List.of(registered, handover));
    }

    private CustodyEvent transfer(String location, String purpose, String notes, String signature) {
        CustodyEvent event = CustodyEvent.builder()
                .evidenceId(evidenceId)
                .fromActor(officerA)
                .toActor(officerB)
                .action("TRANSFERRED")
                .purpose(purpose)
                .location(location)
                .notes(notes)
                .signature(signature)
                .build();
        event.setId(UUID.randomUUID());
        event.setCreatedAt(Instant.parse("2026-03-02T09:30:00Z"));
        return event;
    }
}
