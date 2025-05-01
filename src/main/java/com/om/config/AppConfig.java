package com.om.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class AppConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .securityMatcher("/**") // applies to all endpoints
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").authenticated() // Protect your API endpoints
                .anyRequest().permitAll() // Allow all other requests
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Stateless session management
            )
            .addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class) // JWT Token validation filter
            .csrf(csrf -> csrf.disable()) // Disable CSRF for stateless authentication
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Apply CORS configuration
            .httpBasic(Customizer.withDefaults()) // Basic HTTP authentication
            .formLogin(Customizer.withDefaults()); // Form login (you can customize this if needed)

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Password encoder for securing user passwords
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration cfg = new CorsConfiguration();
            cfg.setAllowedOrigins(Arrays.asList(
                    "http://localhost:3000",   // Local development environments
                    "http://localhost:4000",
                    "http://localhost:4200",
                    "https://ome-commerce.vercel.app" // Production frontend URL
            ));
            cfg.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE")); // Allow specific HTTP methods
            cfg.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization")); // Allow specific headers
            cfg.setAllowCredentials(true); // Allow credentials (e.g., cookies, authorization headers)
            cfg.setExposedHeaders(Arrays.asList("Authorization")); // Expose Authorization header (for JWT)
            cfg.setMaxAge(3600L);  // Cache preflight response for 1 hour (in seconds)
            return cfg;
        };
    }
}
