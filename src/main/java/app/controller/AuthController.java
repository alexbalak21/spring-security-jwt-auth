package app.controller;

import app.service.TokenService;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    //logger
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(AuthController.class);
    private  final TokenService tokenService;


    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication) {
        LOG.info("Generating token for user {}", authentication.getName());
        return this.tokenService.generateToken(authentication);
    }

}