package app.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @NotBlank(message = "Username is required") String username,
    @NotBlank(message = "Password is required") String password
) {
    public String getUsername() {
        return username;
    }
    
    public String getPassword() {
        return password;
    }
}
