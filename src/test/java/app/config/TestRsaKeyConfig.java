package app.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger log = LoggerFactory.getLogger(TestRsaKeyConfig.class);
    private static final String LOG_PREFIX = "[TestRsaKeyConfig] ";

    @Bean
    public RsaKeyProperties rsaKeyProperties() throws NoSuchAlgorithmException {
        log.info("{}Creating RsaKeyProperties bean", LOG_PREFIX);
        try {
            // Generate a new RSA key pair for testing
            log.debug("{}Generating RSA key pair...", LOG_PREFIX);
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            
            log.debug("{}RSA Key Details - Algorithm: {}, Format: {}", 
                    LOG_PREFIX, publicKey.getAlgorithm(), publicKey.getFormat());
            log.trace("{}Public Key: {}", LOG_PREFIX, publicKey);
            
            // Create and return RsaKeyProperties with the generated keys
            RsaKeyProperties rsaKeyProperties = new RsaKeyProperties(publicKey, privateKey);
            log.info("{}Successfully created RsaKeyProperties", LOG_PREFIX);
            return rsaKeyProperties;
            
        } catch (Exception e) {
            log.error("{}Failed to create RsaKeyProperties", LOG_PREFIX, e);
            throw e;
        }
    }
    
    private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        log.debug("{}Generating new RSA key pair with 2048-bit key size", LOG_PREFIX);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            log.trace("{}Successfully generated RSA key pair", LOG_PREFIX);
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            log.error("{}RSA algorithm not available in this environment", LOG_PREFIX, e);
            throw e;
        }
    }
}