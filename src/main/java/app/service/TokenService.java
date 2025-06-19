package app.service;

import app.config.RsaKeyProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for handling JWT token generation, validation, and parsing.
 */
@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final RsaKeyProperties rsaKeyProperties;

    /**
     * Constructor for TokenService.
     *
     * @param jwtEncoder The JWT encoder for creating tokens
     * @param jwtDecoder The JWT decoder for parsing tokens
     * @param rsaKeyProperties RSA key properties for token signing/verification
     */
    public TokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, RsaKeyProperties rsaKeyProperties) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.rsaKeyProperties = rsaKeyProperties;
    }

    /**
     * Generate a JWT token for the authenticated user.
     *
     * @param authentication The authentication object containing user details
     * @return A JWT token as a string
     */
    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    /**
     * Parse a JWT token and return the JWT object.
     *
     * @param token The JWT token to parse
     * @return The parsed JWT object
     * @throws JwtException if the token is invalid
     */
    public Jwt parseToken(String token) {
        return jwtDecoder.decode(token);
    }

    /**
     * Check if a JWT token is valid.
     *
     * @param token The JWT token to validate
     * @return true if the token is valid, false otherwise
     */
    public boolean isTokenValid(String token) {
        try {
            Jwt jwt = parseToken(token);
            // Check if token is expired
            return jwt.getExpiresAt() == null || !jwt.getExpiresAt().isBefore(Instant.now());
        } catch (JwtException e) {
            return false;
        }
    }

    /**
     * Extract the username from a JWT token.
     *
     * @param token The JWT token
     * @return The username (subject) from the token
     */
    public String getUsernameFromToken(String token) {
        Jwt jwt = parseToken(token);
        return jwt.getSubject();
    }
}