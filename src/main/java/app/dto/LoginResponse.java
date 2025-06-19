package app.dto;

public record LoginResponse(
    String token,
    String type
) {
    public static LoginResponse of(String token) {
        return new LoginResponse(token, "Bearer");
    }
}
