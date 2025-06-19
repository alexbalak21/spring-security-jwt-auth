package app.service;

import app.config.RsaKeyProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    private RsaKeyProperties rsaKeyProperties;

    @Mock
    private JwtEncoder jwtEncoder;

    @Mock
    private JwtDecoder jwtDecoder;

    private TokenService tokenService;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Generate test RSA key pair
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        // Create real RsaKeyProperties with test keys
        rsaKeyProperties = new RsaKeyProperties(publicKey, privateKey);
        
        // Initialize service with real RsaKeyProperties and mocked JWT components
        tokenService = new TokenService(jwtEncoder, jwtDecoder, rsaKeyProperties);
    }

    @Test
    void generateToken_ShouldReturnToken() {
        // Arrange
        String expectedToken = "test.jwt.token";
        when(jwtEncoder.encode(any()))
                .thenReturn(new Jwt(
                        expectedToken,
                        Instant.now(),
                        Instant.now().plusSeconds(3600),
                        Map.of("alg", "RS256"),
                        Map.of("sub", "testuser", "scope", "read write")
                ));

        // Act
        String token = tokenService.generateToken(createTestAuthentication());

        // Assert
        assertNotNull(token);
        assertEquals(expectedToken, token);
    }

    @Test
    void parseToken_ShouldReturnJwt() {
        // Arrange
        String token = "test.jwt.token";
        Jwt expectedJwt = new Jwt(
                token,
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "RS256"),
                Map.of("sub", "testuser", "scope", "read write")
        );
        when(jwtDecoder.decode(token)).thenReturn(expectedJwt);

        // Act
        Jwt jwt = tokenService.parseToken(token);

        // Assert
        assertNotNull(jwt);
        assertEquals(token, jwt.getTokenValue());
        assertEquals("testuser", jwt.getSubject());
    }

    @Test
    void isTokenValid_WithValidToken_ShouldReturnTrue() {
        // Arrange
        String token = "valid.token";
        Jwt validJwt = new Jwt(
                token,
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "RS256"),
                Map.of("sub", "testuser", "scope", "read write")
        );
        when(jwtDecoder.decode(token)).thenReturn(validJwt);

        // Act
        boolean isValid = tokenService.isTokenValid(token);

        // Assert
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_WithExpiredToken_ShouldReturnFalse() {
        // Arrange
        String token = "expired.token";
        Jwt expiredJwt = new Jwt(
                token,
                Instant.now().minusSeconds(7200),
                Instant.now().minusSeconds(3600),
                Map.of("alg", "RS256"),
                Map.of("sub", "testuser", "scope", "read write")
        );
        when(jwtDecoder.decode(token)).thenReturn(expiredJwt);

        // Act
        boolean isValid = tokenService.isTokenValid(token);

        // Assert
        assertFalse(isValid);
    }

    @Test
    void getUsernameFromToken_ShouldReturnUsername() {
        // Arrange
        String username = "testuser";
        String token = "test.jwt.token";
        Jwt jwt = new Jwt(
                token,
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "RS256"),
                Map.of("sub", username, "scope", "read write")
        );
        when(jwtDecoder.decode(token)).thenReturn(jwt);

        // Act
        String result = tokenService.getUsernameFromToken(token);

        // Assert
        assertNotNull(result);
        assertEquals(username, result);
    }

    private Authentication createTestAuthentication() {
        return new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }
}