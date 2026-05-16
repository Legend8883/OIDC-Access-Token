package org.legend8883.oidc_accesstoken.token.domain;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.auth.local.LocalUserDetails;
import org.legend8883.oidc_accesstoken.auth.oauth2.OAuth2UserPrincipal;
import org.legend8883.oidc_accesstoken.auth.oauth2.OidcUserPrincipal;
import org.legend8883.oidc_accesstoken.token.api.dto.TokenResponse;
import org.legend8883.oidc_accesstoken.user.db.entities.UserEntity;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenFacadeService {

    private static final String SESSION_ACCESS_TOKEN = "local_access_token";
    private static final String SESSION_REFRESH_TOKEN = "local_refresh_token";

    private final JwtTokenService jwtTokenService;
    private final OAuth2AuthorizedClientService authorizedClientService;

    public TokenResponse resolveTokens(Authentication authentication, HttpSession session) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof LocalUserDetails localUser) {
            return resolveLocalTokens(localUser.getUsername(), session);
        } else if (principal instanceof OidcUserPrincipal oidcUser) {
            return resolveOAuth2Tokens(authentication, oidcUser.getUserEntity(), "google");
        } else if (principal instanceof OAuth2UserPrincipal oauth2User) {
            String provider = resolveProviderName(oauth2User.getUserEntity().getProvider());
            return resolveOAuth2Tokens(authentication, oauth2User.getUserEntity(), provider);
        }

        throw new IllegalStateException("Unknown principal type: " + principal.getClass());
    }

    public TokenResponse refreshTokens(Authentication authentication, HttpSession session) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof LocalUserDetails localUser) {
            String refreshToken = (String) session.getAttribute(SESSION_REFRESH_TOKEN);
            if (refreshToken == null || !jwtTokenService.isTokenValid(refreshToken)) {
                return resolveLocalTokens(localUser.getUsername(), session);
            }
            String newAccess = jwtTokenService.refreshAccessToken(refreshToken);
            session.setAttribute(SESSION_ACCESS_TOKEN, newAccess);
            return TokenResponse.builder()
                    .accessToken(newAccess)
                    .refreshToken(refreshToken)
                    .provider("LOCAL")
                    .isLocal(true)
                    .build();
        } else if (principal instanceof OidcUserPrincipal oidcUser) {
            return resolveOAuth2Tokens(authentication, oidcUser.getUserEntity(), "google");
        } else if (principal instanceof OAuth2UserPrincipal oauth2User) {
            String provider = resolveProviderName(oauth2User.getUserEntity().getProvider());
            return resolveOAuth2Tokens(authentication, oauth2User.getUserEntity(), provider);
        }

        throw new IllegalStateException("Unknown principal type: " + principal.getClass());
    }

    private TokenResponse resolveLocalTokens(String username, HttpSession session) {
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN);
        String refreshToken = (String) session.getAttribute(SESSION_REFRESH_TOKEN);

        if (accessToken == null || !jwtTokenService.isTokenValid(accessToken)) {
            accessToken = jwtTokenService.generateAccessToken(username);
            session.setAttribute(SESSION_ACCESS_TOKEN, accessToken);
        }
        if (refreshToken == null || !jwtTokenService.isTokenValid(refreshToken)) {
            refreshToken = jwtTokenService.generateRefreshToken(username);
            session.setAttribute(SESSION_REFRESH_TOKEN, refreshToken);
        }

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .provider("LOCAL")
                .isLocal(true)
                .build();
    }

    private TokenResponse resolveOAuth2Tokens(Authentication authentication, UserEntity userEntity, String registrationId) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                registrationId, authentication.getName());

        if (client == null) {
            log.warn("No authorized client found for registration={}, user={}", registrationId, userEntity.getUsername());
            return TokenResponse.builder()
                    .accessToken("N/A")
                    .refreshToken("N/A")
                    .provider(registrationId.toUpperCase())
                    .isLocal(false)
                    .build();
        }

        OAuth2AccessToken accessToken = client.getAccessToken();
        OAuth2RefreshToken refreshToken = client.getRefreshToken();

        return TokenResponse.builder()
                .accessToken(accessToken != null ? accessToken.getTokenValue() : "N/A")
                .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : "N/A (not provided by provider)")
                .provider(registrationId.toUpperCase())
                .isLocal(false)
                .build();
    }

    private String resolveProviderName(AuthProvider provider) {
        return switch (provider) {
            case GOOGLE -> "google";
            case GITHUB -> "github";
            case YANDEX -> "yandex";
            default -> throw new IllegalArgumentException("Not an OAuth2 provider: " + provider);
        };
    }
}
