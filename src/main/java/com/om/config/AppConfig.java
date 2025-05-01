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
						.requestMatchers("/api/**").authenticated()
						.anyRequest().permitAll()
				)
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				)
				.addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class)
				.csrf(csrf -> csrf.disable())
				.cors(cors -> cors.configurationSource(corsConfigurationSource()))
				.httpBasic(Customizer.withDefaults())
				.formLogin(Customizer.withDefaults());

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		return request -> {
			CorsConfiguration cfg = new CorsConfiguration();
			cfg.setAllowedOrigins(Arrays.asList(
					"http://localhost:3000",
					"http://localhost:4000",
					"http://localhost:4200",
					"https://ome-commerce.vercel.app"
			));
			cfg.setAllowedMethods(Collections.singletonList("*"));
			cfg.setAllowedHeaders(Collections.singletonList("*"));
			cfg.setAllowCredentials(true);
			cfg.setExposedHeaders(Arrays.asList("Authorization"));
			cfg.setMaxAge(3600L);
			return cfg;
		};
	}
}
