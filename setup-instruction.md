## Audit Log Application setup

1. Prerequisites
    - Java 17 installed
    - Maven installed (or use the provided Maven wrapper if wrapper jar is present)
    - (Optional) OpenSSL for key generation

2. Generate a persistent master key (recommended)
    - openssl rand -base64 32
    - Store the output securely. Example env var: AUDIT_MASTER_KEY=<base64-key>

3. Configure application (one of):
    - Set environment variable: AUDIT_MASTER_KEY=<base64-key>
    - Or set spring property in application.properties: audit.master-key=<base64-key>

4. Run the application
    - mvn -f audit-service-java spring-boot:run
    - Or with wrapper: ./mvnw -f audit-service-java spring-boot:run

5. Run tests
    - mvn -f audit-service-java test

6. Endpoints
    - Swagger UI: http://localhost:8081/swagger-ui.html
    - API base: http://localhost:8081/audit

7. Notes
    - If AUDIT_MASTER_KEY is not provided, the service generates an ephemeral master key which will not survive restarts — do not use in production.
    - For production, use a KMS or secret manager to provide the master key and secure the API with authentication/authorization.

