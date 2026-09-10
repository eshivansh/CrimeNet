package com.crimenet.documents;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Deliberately corrupts a stored document so integrity verification can be shown failing.
 *
 * <p><b>Exists only under the {@code dev} profile.</b> Both this controller and
 * {@link TamperSimulationService} are {@code @Profile("dev")}, so in any other profile the
 * beans are never created and the route returns 404 — there is no flag to forget to turn
 * off, and no way for the endpoint to reach a real deployment.
 *
 * <p>Deliberately not mapped under {@code /api/v1/documents/**} alongside the real document
 * endpoints: a route that damages evidence should not sit in the middle of the ones that
 * protect it.
 */
@RestController
@RequestMapping("/api/dev/tamper")
@Profile("dev")
@RequiredArgsConstructor
public class TamperSimulationController {

    private final TamperSimulationService tamperSimulationService;

    @PostMapping("/documents/{id}")
    public ResponseEntity<ApiResponse<TamperSimulationService.TamperResult>> tamper(
            @PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(tamperSimulationService.tamperWith(id)));
    }
}
