package com.muema.SpringSecurity.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for generating RSA key pairs.
 */
public class KeyGeneratorUtility {

    /**
     * Generates an RSA key pair with a size of 2048 bits.
     *
     * @return A KeyPair object containing the public and private keys.
     * @throws IllegalStateException If the key generation fails.
     */
    public static KeyPair generateRsaKey() {
        KeyPair keyPair;

        try {
            // Create a KeyPairGenerator instance for RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // Initialize the generator with a key size of 2048 bits
            keyPairGenerator.initialize(2048);
            // Generate the key pair
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            // This exception should never occur since "RSA" is a standard algorithm
            throw new IllegalStateException("RSA algorithm not found", e);
        } catch (Exception e) {
            // Catch all other exceptions that may occur during key generation
            throw new IllegalStateException("Key generation failed", e);
        }

        return keyPair; // Return the generated key pair
    }

}
