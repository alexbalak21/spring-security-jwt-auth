package app.config;

import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Configuration properties for RSA keys used for JWT signing and verification.
 * Also exposes the public key via an actuator endpoint.
 */
@ConfigurationProperties(prefix = "rsa")
public record RsaKeyProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

    /**
     * Custom actuator endpoint to expose the public key in PEM format.
     */
    @Component
    @Endpoint(id = "public-key")
    public static class PublicKeyEndpoint {
        private final RsaKeyProperties rsaKeyProperties;

        public PublicKeyEndpoint(RsaKeyProperties rsaKeyProperties) {
            this.rsaKeyProperties = rsaKeyProperties;
        }

        @ReadOperation
        public String getPublicKey() {
            try {
                // Get the public key in X.509 format
                byte[] encoded = rsaKeyProperties.publicKey().getEncoded();
                String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded)
                        + "\n-----END PUBLIC KEY-----";
                return publicKeyPEM;
            } catch (Exception e) {
                throw new RuntimeException("Failed to encode public key", e);
            }
        }
    }
}
