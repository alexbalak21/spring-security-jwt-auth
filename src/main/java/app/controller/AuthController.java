package app.controller;

import app.dto.LoginRequest;
import app.dto.RegisterRequest;
import app.dto.UserResponse;
import app.model.User;
import app.service.AuthenticationService;
import app.service.TokenService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final AuthenticationService authenticationService;

    public AuthController(TokenService tokenService, 
                         AuthenticationManager authenticationManager,
                         AuthenticationService authenticationService) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Login attempt for user: {}", loginRequest.username());

        var authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.username(),
                loginRequest.password()
        );

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        String token = tokenService.generateToken(authentication);
        
        return ResponseEntity.ok(Map.of("AuthToken", token));
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        log.info("Registering new user: {}", registerRequest.username());
        
        if (!registerRequest.passwordsMatch()) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        
        User user = authenticationService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.fromUser(user));
    }
}