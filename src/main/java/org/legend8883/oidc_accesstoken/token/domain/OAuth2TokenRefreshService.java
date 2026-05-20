package org.legend8883.oidc_accesstoken.token.domain;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.token.db.entities.OAuth2AuthorizedClientEntity;
import org.legend8883.oidc_accesstoken.token.db.repositories.OAuth2AuthorizedClientRepository;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2TokenRefreshService {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final WebClient webClient;

    @Transactional
    public String refreshAccessToken(String registrationId, String principalName) {
        OAuth2AuthorizedClientEntity entity = authorizedClientRepository
                .findByClientRegistrationIdAndPrincipalName(registrationId, principalName)
                .orElse(null);

        if (entity == null || entity.getRefreshTokenValue() == null) {
            log.warn("No refresh token found for provider={}, user={}", registrationId, principalName);
            return null;
        }

        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(registrationId);
        if (registration == null) {
            log.warn("Unknown client registration: {}", registrationId);
            return null;
        }

        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("refresh_token", entity.getRefreshTokenValue());
            params.add("client_id", registration.getClientId());
            params.add("client_secret", registration.getClientSecret());

            Map<String, Object> response = webClient.post()
                    .uri(registration.getProviderDetails().getTokenUri())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(params))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            // Логируем полный ответ чтобы видеть что вернул провайдер
            log.info("Raw token response from provider={}: {}", registrationId, response);

            if (response == null || !response.containsKey("access_token")) {
                log.error("Token refresh failed for provider={}, user={}: no access_token in response",
                        registrationId, principalName);
                return null;
            }

            String newAccessToken = (String) response.get("access_token");

            if (response.containsKey("refresh_token")) {
                entity.setRefreshTokenValue((String) response.get("refresh_token"));
                entity.setRefreshTokenIssuedAt(Instant.now());
                authorizedClientRepository.save(entity);
                log.info("Refresh token rotated for provider={}, user={}", registrationId, principalName);
            }

            log.info("Access token refreshed for provider={}, user={}", registrationId, principalName);
            return newAccessToken;

        } catch (Exception e) {
            log.error("Failed to refresh token for provider={}, user={}: {}",
                    registrationId, principalName, e.getMessage());
            return null;
        }
    }
}
