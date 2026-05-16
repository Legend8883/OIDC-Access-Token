package org.legend8883.oidc_accesstoken.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import javax.sql.DataSource;

@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final DataSource dataSource;

    @Bean
    public JdbcOperations jdbcOperations() {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcOperations jdbcOperations,
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
    }
}