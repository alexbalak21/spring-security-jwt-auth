package app.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for the home endpoint that demonstrates protected resource access.
 */
@RestController
public class HomeController {

    /**
     * Public endpoint that doesn't require authentication
     */
    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint. No authentication required.";
    }

    /**
     * Protected endpoint that requires authentication
     */
    @GetMapping("/")
    public Map<String, Object> home(Principal principal, Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        // Basic user info
        response.put("message", "Welcome to the protected resource!");
        response.put("username", principal.getName());
        
        // User roles/authorities
        response.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        
        // JWT token details if available
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("token_issued_at", Instant.ofEpochSecond(jwt.getIssuedAt().getEpochSecond()));
            response.put("token_expires_at", Instant.ofEpochSecond(jwt.getExpiresAt().getEpochSecond()));
            response.put("token_issuer", jwt.getIssuer());
        }
        
        return response;
    }
}
