package com.example.audit.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@org.springframework.context.annotation.Profile("!test")
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        InMemoryUserDetailsManager mgr = new InMemoryUserDetailsManager();
        mgr.createUser(User.withUsername("admin").password(encoder.encode("adminpass")).roles("ADMIN").build());
        mgr.createUser(User.withUsername("user").password(encoder.encode("userpass")).roles("USER").build());
        return mgr;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        MvcRequestMatcher.Builder mvc = new MvcRequestMatcher.Builder(introspector);

        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                .requestMatchers(mvc.pattern(HttpMethod.POST, "/audit/events")).hasAnyRole("USER", "ADMIN")
                .requestMatchers(mvc.pattern(HttpMethod.GET, "/audit/events")).hasAnyRole("USER", "ADMIN")
                .requestMatchers(mvc.pattern(HttpMethod.GET, "/audit/events/**")).hasAnyRole("USER", "ADMIN")
                .requestMatchers(mvc.pattern(HttpMethod.GET, "/audit/verify")).hasAnyRole("USER", "ADMIN")
                // sensitive operations require ADMIN
                .requestMatchers(mvc.pattern(HttpMethod.POST, "/audit/redact")).hasRole("ADMIN")
                .requestMatchers(mvc.pattern(HttpMethod.POST, "/audit/erase")).hasRole("ADMIN")
                .requestMatchers(mvc.pattern(HttpMethod.POST, "/audit/archive")).hasRole("ADMIN")
                // export may be admin-only
                .requestMatchers(mvc.pattern(HttpMethod.GET, "/audit/export")).hasRole("ADMIN")
                // everything else requires authentication
                .anyRequest().authenticated()
            )
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
