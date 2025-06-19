package app.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Utility class for generating JWT tokens for testing purposes.
 */
public class TestJwtTokenUtil {

    private static RSAKey rsaKey;
    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;

    static {
        try {
            // Generate RSA key pair for testing
            rsaKey = new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            privateKey = rsaKey.toRSAPrivateKey();
            publicKey = rsaKey.toRSAPublicKey();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * Generate a JWT token with the specified claims.
     *
     * @param subject   The subject (username) of the token
     * @param issuer    The issuer of the token
     * @param expiresInSeconds Token expiration time in seconds from now
     * @param scopes    List of scopes/authorities
     * @return A signed JWT token
     */
    public static String generateToken(String subject, String issuer, long expiresInSeconds, List<String> scopes) {
        try {
            // Create RSA-signer with the private key
            RSASSASigner signer = new RSASSASigner(privateKey);

            // Prepare JWT with claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(issuer)
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(expiresInSeconds)))
                    .claim("scp", scopes)
                    .claim("jti", UUID.randomUUID().toString())
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .build(),
                    claimsSet);

            // Compute the RSA signature
            signedJWT.sign(signer);

            // Serialize to compact form
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }

    /**
     * Generate a JWT token with default values for testing.
     *
     * @return A signed JWT token with default values
     */
    public static String generateDefaultToken() {
        return generateToken(
                "testuser@example.com",
                "test-issuer",
                3600,
                List.of("read", "write")
        );
    }

    /**
     * Get the public key for JWT verification in tests.
     *
     * @return The RSA public key
     */
    public static RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get the private key for JWT signing in tests.
     *
     * @return The RSA private key
     */
    public static RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Get the JWK (JSON Web Key) representation of the public key.
     *
     * @return The JWK
     */
    public static JWK getJwk() {
        return rsaKey.toPublicJWK();
    }
}
