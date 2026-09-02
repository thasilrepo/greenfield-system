package com.example.audit.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@org.springframework.context.annotation.Profile("!test")
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService users(PasswordEncoder encoder) {
        InMemoryUserDetailsManager mgr = new InMemoryUserDetailsManager();
        mgr.createUser(User.withUsername("admin").password(encoder.encode("adminpass")).roles("ADMIN").build());
        mgr.createUser(User.withUsername("user").password(encoder.encode("userpass")).roles("USER").build());
        return mgr;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                // sensitive operations require ADMIN
                .requestMatchers("/audit/redact", "/audit/erase", "/audit/archive").hasRole("ADMIN")
                // export may be admin-only
                .requestMatchers("/audit/export").hasRole("ADMIN")
                // everything else requires authentication
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
