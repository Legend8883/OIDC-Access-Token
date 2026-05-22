package org.legend8883.oidc_accesstoken.auth.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.user.db.entities.UserEntity;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;
import org.legend8883.oidc_accesstoken.user.domain.UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        AuthProvider provider = resolveProvider(registrationId);

        String providerId = extractProviderId(oauth2User);
        String email = extractEmail(oauth2User, registrationId);
        String name = extractName(oauth2User, registrationId);

        log.info("OAuth2 login via {}: id={}, email={}", registrationId, providerId, email);

        UserEntity appUser = userService.findOrCreateOAuth2User(provider, providerId, name, email);

        String accessToken = userRequest.getAccessToken().getTokenValue();

        return new OAuth2UserPrincipal(oauth2User, appUser, accessToken);
    }

    private AuthProvider resolveProvider(String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "yandex" -> AuthProvider.YANDEX;
            default -> throw new OAuth2AuthenticationException("Unknown provider: " + registrationId);
        };
    }

    private String extractProviderId(OAuth2User user) {
        Object id = user.getAttribute("id");
        return id != null ? id.toString() : user.getName();
    }

    private String extractEmail(OAuth2User user, String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "yandex" -> {
                String email = user.getAttribute("default_email");
                yield email != null ? email : "";
            }
            default -> "";
        };
    }

    private String extractName(OAuth2User user, String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "yandex" -> {
                String login = user.getAttribute("login");
                yield login != null ? login : "yandex_user";
            }
            default -> user.getName();
        };
    }
}