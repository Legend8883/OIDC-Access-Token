package org.legend8883.oidc_accesstoken.config;

import lombok.RequiredArgsConstructor;
import org.legend8883.oidc_accesstoken.token.db.entities.OAuth2AuthorizedClientEntity;
import org.legend8883.oidc_accesstoken.token.db.repositories.OAuth2AuthorizedClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Instant;

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
                // Метод нужен Spring Security для внутренней работы,
                // но мы управляем токенами сами через TokenFacadeService
                return null;
            }

            @Override
            public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient,
                                             org.springframework.security.core.Authentication principal) {
                OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
                if (refreshToken == null) {
                    // GitHub не даёт refresh token — просто пропускаем
                    return;
                }

                String registrationId = authorizedClient.getClientRegistration().getRegistrationId();
                String principalName = principal.getName();

                OAuth2AuthorizedClientEntity entity = authorizedClientRepository
                        .findByClientRegistrationIdAndPrincipalName(registrationId, principalName)
                        .orElse(OAuth2AuthorizedClientEntity.builder()
                                .clientRegistrationId(registrationId)
                                .principalName(principalName)
                                .build());

                entity.setRefreshTokenValue(refreshToken.getTokenValue());
                entity.setRefreshTokenIssuedAt(
                        refreshToken.getIssuedAt() != null ? refreshToken.getIssuedAt() : Instant.now());

                authorizedClientRepository.save(entity);
            }

            @Override
            public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
                authorizedClientRepository.deleteByClientRegistrationIdAndPrincipalName(
                        clientRegistrationId, principalName);
            }
        };
    }
}