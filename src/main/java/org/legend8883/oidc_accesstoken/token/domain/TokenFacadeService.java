package org.legend8883.oidc_accesstoken.token.domain;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.auth.local.LocalUserDetails;
import org.legend8883.oidc_accesstoken.auth.oauth2.OAuth2UserPrincipal;
import org.legend8883.oidc_accesstoken.auth.oauth2.OidcUserPrincipal;
import org.legend8883.oidc_accesstoken.token.api.dto.TokenResponse;
import org.legend8883.oidc_accesstoken.token.db.entities.OAuth2AuthorizedClientEntity;
import org.legend8883.oidc_accesstoken.token.db.repositories.OAuth2AuthorizedClientRepository;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenFacadeService {

    private static final String LOCAL_REGISTRATION_ID = "local";

    private final JwtTokenService jwtTokenService;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final OAuth2TokenRefreshService oauth2TokenRefreshService;

    @Value("${app.jwt.refresh-token-expiration-ms:86400000}")
    private long refreshTokenExpirationMs;

    // ── Публичные методы ──────────────────────────────────────────────────────

    @Transactional
    public TokenResponse resolveTokens(Authentication authentication,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof LocalUserDetails localUser) {
            return resolveLocalTokens(localUser.getUsername(), request, response);
        } else if (principal instanceof OidcUserPrincipal oidcUser) {
            return resolveOAuth2Tokens(oidcUser, "google", request, response);
        } else if (principal instanceof OAuth2UserPrincipal oauth2User) {
            String provider = resolveProviderName(oauth2User.getUserEntity().getProvider());
            return resolveOAuth2Tokens(oauth2User, provider, request, response);
        }

        throw new IllegalStateException("Unknown principal type: " + principal.getClass());
    }

    @Transactional
    public TokenResponse refreshLocalTokens(HttpServletRequest request,
                                            HttpServletResponse response,
                                            Authentication authentication) {
        String username = authentication.getName();
        String refreshTokenValue = extractCookieValue(request, "refresh_token");

        if (refreshTokenValue != null && jwtTokenService.isTokenValid(refreshTokenValue)) {
            OAuth2AuthorizedClientEntity entity = authorizedClientRepository
                    .findByClientRegistrationIdAndPrincipalName(LOCAL_REGISTRATION_ID, username)
                    .orElse(null);

            if (entity != null
                    && refreshTokenValue.equals(entity.getRefreshTokenValue())
                    && entity.getRefreshTokenExpiresAt() != null
                    && entity.getRefreshTokenExpiresAt().isAfter(Instant.now())) {

                String newAccess = jwtTokenService.refreshAccessToken(refreshTokenValue);
                setAccessTokenCookie(response, newAccess);

                return TokenResponse.builder()
                        .accessToken(newAccess)
                        .refreshToken(refreshTokenValue)
                        .provider("LOCAL")
                        .isLocal(true)
                        .build();
            }
        }

        return issueLocalTokenPair(username, response);
    }

    @Transactional
    public TokenResponse refreshOAuth2Tokens(Authentication authentication,
                                             HttpServletResponse response) {
        Object principal = authentication.getPrincipal();

        String username;
        String registrationId;

        if (principal instanceof OidcUserPrincipal oidcUser) {
            username = oidcUser.getUserEntity().getUsername();
            registrationId = "google";
        } else if (principal instanceof OAuth2UserPrincipal oauth2User) {
            username = oauth2User.getUserEntity().getUsername();
            registrationId = resolveProviderName(oauth2User.getUserEntity().getProvider());
        } else {
            throw new IllegalStateException("Not an OAuth2 principal: " + principal.getClass());
        }

        String newAccessToken = oauth2TokenRefreshService.refreshAccessToken(registrationId, username);

        if (newAccessToken != null) {
            // Кладём свежий access token в cookie чтобы /token/current-access его показал
            setAccessTokenCookie(response, newAccessToken);
        }

        return TokenResponse.builder()
                .accessToken(newAccessToken != null ? newAccessToken : "Failed to refresh — check logs")
                .refreshToken("(stored in DB)")
                .provider(registrationId.toUpperCase())
                .isLocal(false)
                .build();
    }

    // ── Приватные методы ──────────────────────────────────────────────────────

    private TokenResponse resolveLocalTokens(String username,
                                             HttpServletRequest request,
                                             HttpServletResponse response) {
        String existingAccess = extractCookieValue(request, "access_token");
        if (existingAccess != null && jwtTokenService.isTokenValid(existingAccess)) {
            String storedRefresh = authorizedClientRepository
                    .findByClientRegistrationIdAndPrincipalName(LOCAL_REGISTRATION_ID, username)
                    .map(OAuth2AuthorizedClientEntity::getRefreshTokenValue)
                    .orElse("(stored in DB)");
            return TokenResponse.builder()
                    .accessToken(existingAccess)
                    .refreshToken(storedRefresh)
                    .provider("LOCAL")
                    .isLocal(true)
                    .build();
        }

        return issueLocalTokenPair(username, response);
    }

    private TokenResponse resolveOAuth2Tokens(Object principal,
                                              String registrationId,
                                              HttpServletRequest request,
                                              HttpServletResponse response) {
        // Пробуем взять access token из cookie (если уже заходили на страницу)
        String accessToken = extractCookieValue(request, "access_token");

        // Если в cookie нет — берём из principal (работает только сразу после логина,
        // пока Spring не десериализовал principal из сессии без поля accessToken)
        if (accessToken == null || accessToken.isBlank()) {
            if (principal instanceof OidcUserPrincipal oidcUser) {
                accessToken = oidcUser.getAccessToken();
            } else if (principal instanceof OAuth2UserPrincipal oauth2User) {
                accessToken = oauth2User.getAccessToken();
            }
        }

        // Кладём в cookie чтобы при следующих запросах он был доступен
        if (accessToken != null && !accessToken.isBlank()) {
            setAccessTokenCookie(response, accessToken);
        }

        String principalName = principal instanceof OidcUserPrincipal o
                ? o.getUserEntity().getUsername()
                : ((OAuth2UserPrincipal) principal).getUserEntity().getUsername();

        String refreshToken = authorizedClientRepository
                .findByClientRegistrationIdAndPrincipalName(registrationId, principalName)
                .map(entity -> entity.getRefreshTokenValue() != null
                        ? entity.getRefreshTokenValue()
                        : "N/A — provider did not supply refresh token (GitHub)")
                .orElse("N/A");

        return TokenResponse.builder()
                .accessToken(accessToken != null ? accessToken : "N/A — please re-login")
                .refreshToken(refreshToken)
                .provider(registrationId.toUpperCase())
                .isLocal(false)
                .build();
    }

    @Transactional
    public TokenResponse issueLocalTokenPair(String username, HttpServletResponse response) {
        String accessToken = jwtTokenService.generateAccessToken(username);
        String refreshToken = jwtTokenService.generateRefreshToken(username);
        Instant now = Instant.now();

        setAccessTokenCookie(response, accessToken);

        OAuth2AuthorizedClientEntity entity = authorizedClientRepository
                .findByClientRegistrationIdAndPrincipalName(LOCAL_REGISTRATION_ID, username)
                .orElse(OAuth2AuthorizedClientEntity.builder()
                        .clientRegistrationId(LOCAL_REGISTRATION_ID)
                        .principalName(username)
                        .build());

        entity.setRefreshTokenValue(refreshToken);
        entity.setRefreshTokenIssuedAt(now);
        entity.setRefreshTokenExpiresAt(now.plusMillis(refreshTokenExpirationMs));
        authorizedClientRepository.save(entity);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .provider("LOCAL")
                .isLocal(true)
                .build();
    }

    private void setAccessTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("access_token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(900); // 15 минут
        // cookie.setSecure(true); // включить в production (HTTPS)
        response.addCookie(cookie);
    }

    public String extractCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
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