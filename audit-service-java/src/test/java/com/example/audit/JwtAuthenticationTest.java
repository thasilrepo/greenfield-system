package com.example.audit;

import com.example.audit.config.JwtAuthenticationEntryPoint;
import com.example.audit.config.JwtAuthenticationFilter;
import com.example.audit.config.JwtTokenProvider;
import com.example.audit.web.AuthController;
import com.example.audit.web.ErrorResponse;
import com.example.audit.web.LoginRequest;
import com.example.audit.web.LoginResponse;
import com.example.audit.web.TokenValidationResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenProvider tokenProvider;

    @InjectMocks
    private AuthController authController;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void jwtTokenProvider_generatesValidTokenAndRoundTripsClaims() {
        JwtTokenProvider provider = new JwtTokenProvider();
        ReflectionTestUtils.setField(provider, "jwtSecret", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        ReflectionTestUtils.setField(provider, "jwtExpiration", 60_000L);

        Authentication auth = new TestingAuthenticationToken(
                "admin",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"))
        );

        String token = provider.generateToken(auth);

        assertThat(token).isNotBlank();
        assertTrue(provider.validateToken(token));
        assertThat(provider.getUsernameFromToken(token)).isEqualTo("admin");
        assertThat(provider.getRolesFromToken(token)).containsExactly("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void jwtTokenProvider_rejectsMalformedToken() {
        JwtTokenProvider provider = new JwtTokenProvider();
        ReflectionTestUtils.setField(provider, "jwtSecret", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        assertFalse(provider.validateToken("not-a-valid-token"));
    }

    @Test
    void jwtAuthenticationFilter_setsAuthenticationForValidBearerToken() throws Exception {
        JwtTokenProvider provider = new JwtTokenProvider();
        ReflectionTestUtils.setField(provider, "jwtSecret", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        ReflectionTestUtils.setField(provider, "jwtExpiration", 60_000L);

        Authentication auth = new TestingAuthenticationToken(
                "user",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        String token = provider.generateToken(auth);

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        ReflectionTestUtils.setField(filter, "tokenProvider", provider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        ReflectionTestUtils.invokeMethod(filter, "doFilterInternal", request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("user");
        verify(chain).doFilter(request, response);
    }

    @Test
    void jwtAuthenticationFilter_ignoresMissingOrInvalidAuthorizationHeader() throws Exception {
        JwtTokenProvider provider = new JwtTokenProvider();
        ReflectionTestUtils.setField(provider, "jwtSecret", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        ReflectionTestUtils.setField(filter, "tokenProvider", provider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        ReflectionTestUtils.invokeMethod(filter, "doFilterInternal", request, response, chain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        request.addHeader("Authorization", "Bearer invalid-token");
        ReflectionTestUtils.invokeMethod(filter, "doFilterInternal", request, response, chain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void jwtAuthenticationEntryPoint_returnsUnauthorizedJsonPayload() throws Exception {
        JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/audit/events");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new BadCredentialsException("Bad credentials"));

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentType()).isEqualTo("application/json");

        Map<String, Object> body = new ObjectMapper().readValue(response.getContentAsString(), Map.class);
        assertThat(body.get("status")).isEqualTo(401);
        assertThat(body.get("error")).isEqualTo("Unauthorized");
        assertThat(body.get("path")).isEqualTo("/audit/events");
    }

    @Test
    void authController_loginReturnsTokenForValidCredentials() {
        Authentication authentication = new TestingAuthenticationToken(
                "admin",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"))
        );
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(tokenProvider.generateToken(authentication)).thenReturn("jwt-token");

        ResponseEntity<?> response = authController.login(new LoginRequest("admin", "adminpass"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        LoginResponse body = (LoginResponse) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getToken()).isEqualTo("jwt-token");
        assertThat(body.getUsername()).isEqualTo("admin");
        assertThat(body.getRoles()).contains("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void authController_loginReturnsUnauthorizedForBadCredentials() {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        ResponseEntity<?> response = authController.login(new LoginRequest("admin", "wrongpass"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
    }

    @Test
    void authController_validateTokenReturnsValidWhenJWTIsAccepted() {
        when(tokenProvider.validateToken("jwt-token")).thenReturn(true);
        when(tokenProvider.getUsernameFromToken("jwt-token")).thenReturn("admin");
        when(tokenProvider.getRolesFromToken("jwt-token")).thenReturn(List.of("ROLE_ADMIN"));

        ResponseEntity<?> response = authController.validateToken("Bearer jwt-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        TokenValidationResponse body = (TokenValidationResponse) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.isValid()).isTrue();
        assertThat(body.getUsername()).isEqualTo("admin");
        assertThat(body.getRoles()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void authController_validateTokenReturnsUnauthorizedWhenJWTIsInvalid() {
        when(tokenProvider.validateToken("bad-token")).thenReturn(false);

        ResponseEntity<?> response = authController.validateToken("Bearer bad-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        TokenValidationResponse body = (TokenValidationResponse) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.isValid()).isFalse();
    }

    @Test
    void authController_validateTokenReturnsUnauthorizedWhenHeaderThrowsException() {
        when(tokenProvider.validateToken("bad-token")).thenThrow(new RuntimeException("token parse failed"));

        ResponseEntity<?> response = authController.validateToken("Bearer bad-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        TokenValidationResponse body = (TokenValidationResponse) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.isValid()).isFalse();
        assertThat(body.getUsername()).isNull();
        assertThat(body.getRoles()).isNull();
    }

    @Test
    void webModelBeans_coverConstructorsSettersAndGetters() {
        ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.setError("error");
        errorResponse.setMessage("message");
        assertThat(errorResponse.getError()).isEqualTo("error");
        assertThat(errorResponse.getMessage()).isEqualTo("message");

        ErrorResponse errorResponseWithArgs = new ErrorResponse("auth", "bad creds");
        assertThat(errorResponseWithArgs.getError()).isEqualTo("auth");
        assertThat(errorResponseWithArgs.getMessage()).isEqualTo("bad creds");

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("user");
        loginRequest.setPassword("pass");
        assertThat(loginRequest.getUsername()).isEqualTo("user");
        assertThat(loginRequest.getPassword()).isEqualTo("pass");

        LoginRequest loginRequestWithArgs = new LoginRequest("admin", "adminpass");
        assertThat(loginRequestWithArgs.getUsername()).isEqualTo("admin");
        assertThat(loginRequestWithArgs.getPassword()).isEqualTo("adminpass");

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken("jwt");
        loginResponse.setType("Bearer");
        loginResponse.setUsername("admin");
        loginResponse.setRoles(List.of("ROLE_ADMIN"));
        assertThat(loginResponse.getToken()).isEqualTo("jwt");
        assertThat(loginResponse.getType()).isEqualTo("Bearer");
        assertThat(loginResponse.getUsername()).isEqualTo("admin");
        assertThat(loginResponse.getRoles()).containsExactly("ROLE_ADMIN");

        LoginResponse loginResponseWithArgs = new LoginResponse("jwt", "admin", List.of("ROLE_USER"));
        assertThat(loginResponseWithArgs.getToken()).isEqualTo("jwt");
        assertThat(loginResponseWithArgs.getType()).isEqualTo("Bearer");
        assertThat(loginResponseWithArgs.getUsername()).isEqualTo("admin");
        assertThat(loginResponseWithArgs.getRoles()).containsExactly("ROLE_USER");

        LoginResponse loginResponseWithFourArgs = new LoginResponse("jwt", "Bearer", "admin", List.of("ROLE_ADMIN", "ROLE_USER"));
        assertThat(loginResponseWithFourArgs.getToken()).isEqualTo("jwt");
        assertThat(loginResponseWithFourArgs.getType()).isEqualTo("Bearer");
        assertThat(loginResponseWithFourArgs.getUsername()).isEqualTo("admin");
        assertThat(loginResponseWithFourArgs.getRoles()).containsExactly("ROLE_ADMIN", "ROLE_USER");

        TokenValidationResponse tokenValidationResponse = new TokenValidationResponse();
        tokenValidationResponse.setValid(true);
        tokenValidationResponse.setUsername("user");
        tokenValidationResponse.setRoles(List.of("ROLE_USER"));
        assertThat(tokenValidationResponse.isValid()).isTrue();
        assertThat(tokenValidationResponse.getUsername()).isEqualTo("user");
        assertThat(tokenValidationResponse.getRoles()).containsExactly("ROLE_USER");

        TokenValidationResponse tokenValidationResponseWithArgs = new TokenValidationResponse(false, "admin", List.of("ROLE_ADMIN"));
        assertThat(tokenValidationResponseWithArgs.isValid()).isFalse();
        assertThat(tokenValidationResponseWithArgs.getUsername()).isEqualTo("admin");
        assertThat(tokenValidationResponseWithArgs.getRoles()).containsExactly("ROLE_ADMIN");
    }
}
