package com.example.audit.config;

import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI auditOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Audit Log Service API")
                        .version("1.0.0")
                        .description("API for append-only audit log with redaction, erase, archive, export and verification endpoints.")
                        .contact(new Contact().name("Thasil Mohamed").email("thasilmohamed641@gmail.com"))
                );
    }
}
