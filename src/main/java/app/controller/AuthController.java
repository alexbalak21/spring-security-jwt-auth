package app.controller;

import app.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controller responsible for handling authentication-related requests.
 * This includes user login and JWT token generation.
 */
@RestController // Marks this class as a REST controller that returns response bodies
public class AuthController {

    // Logger for this class to log important information
    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    
    // Service responsible for JWT token generation
    private final TokenService tokenService;

    /**
     * Constructor for dependency injection
     * @param tokenService Service for JWT token operations
     */
    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * Handles user login and returns a JWT token upon successful authentication.
     * 
     * @param authentication Spring's authentication object containing user details
     * @return ResponseEntity containing the JWT token if authentication is successful
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> token(Authentication authentication) {
        // Log the login attempt
        LOG.info("Generating token for user {}", authentication.getName());
        
        // Generate a JWT token for the authenticated user
        String token = this.tokenService.generateToken(authentication);
        
        // Return the token in the response body with a 200 OK status
        return ResponseEntity.ok(Map.of("token", token));
    }
}