# JWT Authentication Implementation

## Overview
This guide describes the JWT token-based authentication added to the Audit Service. JWT (JSON Web Token) provides stateless, scalable authentication suitable for REST APIs.

## Changes Made

### 1. Dependencies Added
Added to `pom.xml`:
- `jjwt-api` (0.12.3) - JWT library
- `jjwt-impl` (0.12.3) - Implementation
- `jjwt-jackson` (0.12.3) - JSON serialization

### 2. New Components Created

#### `JwtTokenProvider` (`config/JwtTokenProvider.java`)
- Generates JWT tokens from authenticated users
- Validates JWT tokens
- Extracts username and roles from tokens
- Uses HS512 signature algorithm

#### `JwtAuthenticationFilter` (`config/JwtAuthenticationFilter.java`)
- Processes incoming requests for JWT tokens
- Validates tokens and sets authentication context
- Extracts bearer token from `Authorization` header

#### `JwtAuthenticationEntryPoint` (`config/JwtAuthenticationEntryPoint.java`)
- Handles 401 Unauthorized responses
- Returns proper JSON error responses instead of default HTML

#### `AuthController` (`web/AuthController.java`)
- `/auth/login` - POST endpoint for token generation
- `/auth/validate` - GET endpoint to validate token (optional utility endpoint)

#### DTOs
- `LoginRequest` - Contains username and password
- `LoginResponse` - Contains JWT token, type, username, and roles
- `ErrorResponse` - Error message container
- `TokenValidationResponse` - Token validation result

### 3. Updated Components

#### `SecurityConfig` (`config/SecurityConfig.java`)
Changed from HTTP Basic to JWT:
- Removed `.httpBasic()`
- Added JWT filter before UsernamePasswordAuthenticationFilter
- Made `/auth/login` endpoint public
- Added JwtAuthenticationEntryPoint for 401 handling

#### `application.properties`
Added JWT configuration:
```properties
jwt.expiration=86400000  # 24 hours in milliseconds
jwt.secret=<32+ character secret key>
```

## Configuration

### 1. JWT Secret Key
**For Development:**
Use the default or set in `application.properties`:
```properties
jwt.secret=your-secret-key-for-jwt-should-be-at-least-32-characters-long
```

**For Production:**
Set via environment variable (recommended):
```bash
export JWT_SECRET="your-secret-key-for-jwt-should-be-at-least-32-characters-long"
```

Then use in application with `@Value("${jwt.secret}")` or `@Value("${JWT_SECRET:default}")`

Generate a strong key:
```bash
openssl rand -base64 32
```

### 2. Token Expiration
Default: 86400000 milliseconds (24 hours)
Customize in `application.properties`:
```properties
jwt.expiration=3600000  # 1 hour
```

## Usage

### 1. Login and Get Token
```bash
curl -X POST http://localhost:8081/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpass"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbIlJPTEVfQURNSU4iXSwiaWF0IjoxNjkzNDMyMzQ1LCJleHAiOjE2OTM1MTg3NDV9.2tFVgTLH...",
  "type": "Bearer",
  "username": "admin",
  "roles": ["ROLE_ADMIN"]
}
```

### 2. Use Token to Access Protected Endpoints
```bash
curl -X GET http://localhost:8081/audit/events \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..."
```

### 3. Validate Token (Optional)
```bash
curl -X GET http://localhost:8081/auth/validate \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..."
```

Response (valid token):
```json
{
  "valid": true,
  "username": "admin",
  "roles": ["ROLE_ADMIN"]
}
```

## User Credentials

### Default In-Memory Users
- **admin** / **adminpass** (Role: ADMIN)
- **user** / **userpass** (Role: USER)

### Production Recommendation
Replace `InMemoryUserDetailsManager` in `SecurityConfig` with:
- Database-backed UserDetailsService
- LDAP integration
- External auth provider

## Endpoint Authorization

| Endpoint | Method | Public | User | Admin |
|----------|--------|--------|------|-------|
| `/auth/login` | POST | ✅ | - | - |
| `/auth/validate` | GET | ✅ | - | - |
| `/audit/events` | POST | - | ✅ | ✅ |
| `/audit/events` | GET | - | ✅ | ✅ |
| `/audit/events/{id}` | GET | - | ✅ | ✅ |
| `/audit/verify` | GET | - | ✅ | ✅ |
| `/audit/redact` | POST | - | - | ✅ |
| `/audit/erase` | POST | - | - | ✅ |
| `/audit/archive` | POST | - | - | ✅ |
| `/audit/export` | GET | - | - | ✅ |

## Error Responses

### 401 Unauthorized (Missing or Invalid Token)
```json
{
  "status": 401,
  "error": "Unauthorized",
  "message": "Full authentication is required to access this resource",
  "path": "/audit/events"
}
```

### 401 Unauthorized (Invalid Credentials at Login)
```json
{
  "error": "Invalid credentials",
  "message": "Authentication failed"
}
```

## Testing

### Run Tests
```bash
mvn -f audit-service-java test
```

Tests use `TestSecurityConfig` profile which maintains HTTP Basic auth for testing purposes.

### Manual Testing with Swagger UI
1. Start the application: `mvn -f audit-service-java spring-boot:run`
2. Open Swagger UI: http://localhost:8081/swagger-ui.html
3. Login via `/auth/login` endpoint
4. Use returned token in subsequent requests

## Token Claims

Each JWT token contains:
- **sub** (subject) - Username
- **roles** - List of user roles (e.g., ROLE_ADMIN, ROLE_USER)
- **iat** (issued at) - Token creation timestamp
- **exp** (expiration) - Token expiration timestamp

Example decoded payload:
```json
{
  "sub": "admin",
  "roles": ["ROLE_ADMIN"],
  "iat": 1693432345,
  "exp": 1693518745
}
```

## Security Considerations

1. **HTTPS Required** - Use HTTPS in production to prevent token interception
2. **Secret Key Management** - Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) in production
3. **Token Storage** - Store tokens securely on client (HttpOnly cookies preferred over localStorage)
4. **Token Refresh** - Consider implementing token refresh endpoint for long-lived sessions
5. **Revocation** - No built-in revocation; consider token blacklist for logout
6. **Signature Verification** - Always validate token signature (implemented via `validateToken()`)

## Migration from HTTP Basic to JWT

If existing clients use HTTP Basic:
1. Provide transition period with both auth methods enabled
2. Add bearer token support alongside basic auth
3. Redirect basic auth requests to token endpoint
4. Document new endpoint in API documentation

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Invalid JWT token" | Verify secret key matches between app and test |
| Token expired | Check `jwt.expiration` configuration |
| 401 on valid token | Ensure `Authorization: Bearer <token>` format |
| CORS issues | Configure Spring CORS if calling from different origin |

## Next Steps

1. Set `jwt.secret` environment variable for your environment
2. Update client applications to use `/auth/login` endpoint
3. Replace in-memory users with persistent user store
4. Implement token refresh mechanism if needed
5. Add logout/token revocation functionality
6. Consider adding rate limiting to login endpoint
