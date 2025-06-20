package app.dto;

import app.model.User;

import java.time.LocalDateTime;

public record UserResponse(
    Long id,
    String username,
    String role,
    boolean enabled,
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {
    public static UserResponse fromUser(User user) {
        return new UserResponse(
            user.getId(),
            user.getUsername(),
            user.getRole().name(),
            user.isEnabled(),
            user.getCreatedAt(),
            user.getUpdatedAt()
        );
    }
}
