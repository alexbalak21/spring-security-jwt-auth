package app.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Test configuration for RSA key properties.
 * This configuration is only active during testing.
 */
@Configuration
@Profile("test")
@EnableConfigurationProperties
public class TestRsaKeyConfig {

    @Bean
    public RsaKeyProperties rsaKeyProperties() throws NoSuchAlgorithmException {
        // Generate a new RSA key pair for testing
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        // Create and return RsaKeyProperties with the generated keys
        return new RsaKeyProperties(publicKey, privateKey);
    }
    
    private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}