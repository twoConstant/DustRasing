package com.ssafy.rasingdust.global.config.springdoc;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("local")
@Configuration
@OpenAPIDefinition(
    info = @Info(title = "Dust Rasing API", version = "v1", description = "SSAFY 특화 프로젝트"),
    security = @SecurityRequirement(name = "Authorization"),
    servers = {
        @Server(url="http://localhost:8081/api", description = "Local Swagger")
    }
)
@SecurityScheme(name = "Authorization",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    in = SecuritySchemeIn.HEADER)
public class SpringDocLocalConfig {

        @Bean
        public GroupedOpenApi publicApi() {
            return GroupedOpenApi.builder()
                .group("spring")
                .pathsToMatch("/**")
                .build();
        }


}
