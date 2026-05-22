package org.legend8883.oidc_accesstoken.config;

import lombok.RequiredArgsConstructor;
import org.legend8883.oidc_accesstoken.token.db.repositories.OAuth2AuthorizedClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new OAuth2AuthorizedClientService() {

            @Override
            public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(
                    String clientRegistrationId, String principalName) {
                return null;
            }

            @Override
            public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient,
                                             Authentication principal) {
                // Ничего не делаем — провайдерские токены нам не нужны
            }

            @Override
            public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
                authorizedClientRepository.deleteByClientRegistrationIdAndPrincipalName(
                        clientRegistrationId, principalName);
            }
        };
    }
}