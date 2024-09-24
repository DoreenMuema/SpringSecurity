package com.muema.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.muema.SpringSecurity.utils.RSAKeyProperties;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final RSAKeyProperties keys; // Holds the RSA key properties for JWT signing and verification

    public SecurityConfiguration(RSAKeyProperties keys) {
        this.keys = keys; // Injects the RSA key properties
    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // Configures HTTP security for the application
        http
                .csrf(csrf -> csrf.disable()) // Disables CSRF protection for simplicity (consider enabling it for production)
                .authorizeHttpRequests(auth -> {
                    // Configures URL access permissions
                    auth.requestMatchers("/auth/**").permitAll(); // Allows access to authentication endpoints
                    auth.requestMatchers("/admin/**").hasRole("ADMIN"); // Only ADMIN can access admin endpoints
                    auth.requestMatchers("/user/**").hasAnyRole("ADMIN", "USER"); // ADMIN and USER can access user endpoints
                    auth.anyRequest().authenticated(); // Any other request requires authentication
                });

        http.oauth2ResourceServer()
                .jwt() // Configures the application as an OAuth2 Resource Server
                .jwtAuthenticationConverter(jwtAuthenticationConverter()); // Sets the JWT authentication converter

        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Configures stateless session management
        );

        return http.build(); // Builds the security filter chain
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Returns a password encoder that uses BCrypt hashing
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authManager(UserDetailsService detailsService) {
        // Configures the authentication manager with a DAO provider
        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(detailsService); // Sets the user details service
        daoProvider.setPasswordEncoder(passwordEncoder()); // Sets the password encoder
        return new ProviderManager(daoProvider); // Returns the authentication manager
    }


    @Bean
    public JwtDecoder jwtDecoder() {
        // Returns a JWT decoder that uses the public key for verification
        return NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        // Configures a JWT encoder that uses the private key for signing
        JWK jwk = new RSAKey.Builder(keys.getPublicKey()).privateKey(keys.getPrivateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks); // Returns the JWT encoder
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        // Configures how roles are extracted from the JWT
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles"); // Specifies the claim name for roles
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_"); // Prefix for roles
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter); // Sets the converter
        return jwtConverter; // Returns the configured converter
    }
}
