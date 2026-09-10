package com.crimenet.cases;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Persons attached to a case — victims, witnesses, accused, informants.
 *
 * <p>Row visibility here is decided by PostgreSQL, not by this controller. See
 * {@link CasePersonService} for why reads are left to the row-level security policy.
 */
@RestController
@RequestMapping("/api/v1/cases/{caseId}/persons")
@RequiredArgsConstructor
public class CasePersonController {

    private final CasePersonService casePersonService;

    @PostMapping
    public ResponseEntity<ApiResponse<PersonResponse>> add(
            @PathVariable UUID caseId,
            @RequestBody CasePersonService.AddPersonRequest request) {
        CasePerson person = casePersonService.addPerson(caseId, request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok(PersonResponse.from(person)));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<PersonResponse>>> list(@PathVariable UUID caseId) {
        List<PersonResponse> people = casePersonService.listPersons(caseId).stream()
                .map(PersonResponse::from)
                .toList();
        return ResponseEntity.ok(ApiResponse.ok(people));
    }

    /**
     * Explains the row-level security outcome for the current caller on this case.
     */
    @GetMapping("/access")
    public ResponseEntity<ApiResponse<CasePersonService.RlsStatus>> access(@PathVariable UUID caseId) {
        return ResponseEntity.ok(ApiResponse.ok(casePersonService.describeAccess(caseId)));
    }

    /**
     * Field names here say what the columns actually hold. The underlying columns are
     * named {@code *_encrypted}, but nothing encrypts them yet — calling the response
     * field {@code idNumber} avoids implying a protection that does not exist.
     */
    public record PersonResponse(
            UUID id,
            UUID caseId,
            String personName,
            String roleType,
            String idType,
            String idNumber,
            String contact,
            String address,
            String notes,
            String status,
            Instant createdAt
    ) {
        public static PersonResponse from(CasePerson p) {
            return new PersonResponse(
                    p.getId(),
                    p.getCaseId(),
                    p.getPersonName(),
                    p.getRoleType(),
                    p.getIdType(),
                    p.getIdNumberEncrypted(),
                    p.getContactEncrypted(),
                    p.getAddressEncrypted(),
                    p.getNotes(),
                    p.getStatus(),
                    p.getCreatedAt());
        }
    }
}
