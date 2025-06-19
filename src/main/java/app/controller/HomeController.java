package app.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for the home endpoint that demonstrates protected resource access.
 */
@RestController
public class HomeController {
    private static final Logger log = LoggerFactory.getLogger(HomeController.class);

    /**
     * Public endpoint that doesn't require authentication
     */
    @GetMapping("/public")
    public String publicEndpoint() {
        log.info("Accessing public endpoint");
        return "This is a public endpoint. No authentication required.";
    }

    /**
     * Protected endpoint that requires authentication
     */
    @GetMapping("/")
    @PreAuthorize("hasAnyAuthority('SCOPE_read', 'SCOPE_write')")
    public Map<String, Object> home(Principal principal, Authentication authentication) {
        log.info("=== Home Controller Invoked ===");
        log.info("Principal: {}", principal);
        log.info("Authentication: {}", authentication);
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Basic user info
            String username = principal != null ? principal.getName() : "anonymous";
            log.info("User '{}' accessing home endpoint", username);
            
            response.put("message", "Welcome to the protected resource!");
            response.put("username", username);
            
            // User roles/authorities
            if (authentication != null && authentication.getAuthorities() != null) {
                log.info("User authorities: {}", authentication.getAuthorities());
                response.put("authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()));
            } else {
                log.warn("No authorities found in authentication object");
                response.put("authorities", List.of());
            }
            
            // JWT token details if available
            if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
                Jwt jwt = (Jwt) authentication.getPrincipal();
                log.info("JWT Token details - Issuer: {}, Issued At: {}, Expires At: {}", 
                        jwt.getIssuer(), jwt.getIssuedAt(), jwt.getExpiresAt());
                        
                response.put("token_issued_at", Instant.ofEpochSecond(jwt.getIssuedAt().getEpochSecond()));
                response.put("token_expires_at", Instant.ofEpochSecond(jwt.getExpiresAt().getEpochSecond()));
                response.put("token_issuer", jwt.getIssuer());
            } else if (authentication != null) {
                log.info("Authentication principal is not a JWT token. Principal type: {}", 
                        authentication.getPrincipal() != null ? 
                        authentication.getPrincipal().getClass().getName() : "null");
            } else {
                log.warn("Authentication object is null");
            }
            
            log.info("Response: {}", response);
            return response;
            
        } catch (Exception e) {
            log.error("Error in home controller", e);
            throw e;
        }
    }
}
