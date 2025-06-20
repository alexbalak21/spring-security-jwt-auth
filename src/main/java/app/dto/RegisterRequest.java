package app.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    String username,

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 120, message = "Password must be between 6 and 120 characters")
    String password,

    @NotBlank(message = "Password confirmation is required")
    String confirmPassword
) {
    public boolean passwordsMatch() {
        return password != null && password.equals(confirmPassword);
    }
}
