package com.crimenet.identity;

import com.crimenet.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> me() {
        AppUser user = userService.getCurrentUser();
        return ResponseEntity.ok(ApiResponse.ok(UserResponse.from(user)));
    }

    /**
     * List the users in the caller's own organization.
     *
     * <p>Case assignment and custody transfer both identify their target by internal
     * user id, so callers need a way to discover those ids. Scoped to the caller's org
     * so this cannot be used to enumerate users across organizations.
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<UserResponse>>> list() {
        AppUser currentUser = userService.getCurrentUser();
        List<UserResponse> users = userService.listUsers(currentUser.getOrgId()).stream()
                .map(UserResponse::from)
                .toList();
        return ResponseEntity.ok(ApiResponse.ok(users));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserResponse>> get(@PathVariable UUID id) {
        AppUser user = userService.getUser(id);
        return ResponseEntity.ok(ApiResponse.ok(UserResponse.from(user)));
    }

    public record UserResponse(
            UUID id,
            UUID orgId,
            String displayName,
            String email,
            String status
    ) {
        public static UserResponse from(AppUser user) {
            return new UserResponse(
                    user.getId(),
                    user.getOrgId(),
                    user.getDisplayName(),
                    user.getEmail(),
                    user.getStatus()
            );
        }
    }
}
