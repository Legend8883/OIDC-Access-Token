package org.legend8883.oidc_accesstoken.token.domain;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    private final JwtTokenService jwtTokenService;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Value("${app.jwt.refresh-token-expiration-ms:86400000}")
    private long refreshTokenExpirationMs;

    @Transactional
    public TokenResponse resolveTokens(Authentication authentication,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        String username = authentication.getName();
        String registrationId = resolveRegistrationId(authentication);

        String accessToken = extractCookieValue(request, "access_token");

        String refreshToken = authorizedClientRepository
                .findByClientRegistrationIdAndPrincipalName(registrationId, username)
                .map(OAuth2AuthorizedClientEntity::getRefreshTokenValue)
                .orElse("(нет в БД)");

        return TokenResponse.builder()
                .accessToken(accessToken != null ? accessToken : "Нет токена — войдите заново")
                .refreshToken(refreshToken)
                .provider(registrationId.toUpperCase())
                .isLocal("local".equals(registrationId))
                .build();
    }

    @Transactional
    public TokenResponse refreshTokens(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) {
        String username = authentication.getName();
        String registrationId = resolveRegistrationId(authentication);

        String refreshTokenValue = extractCookieValue(request, "refresh_token");

        if (refreshTokenValue != null && jwtTokenService.isTokenValid(refreshTokenValue)) {
            OAuth2AuthorizedClientEntity entity = authorizedClientRepository
                    .findByClientRegistrationIdAndPrincipalName(registrationId, username)
                    .orElse(null);

            if (entity != null
                    && refreshTokenValue.equals(entity.getRefreshTokenValue())
                    && entity.getRefreshTokenExpiresAt() != null
                    && entity.getRefreshTokenExpiresAt().isAfter(Instant.now())) {

                String newAccess = jwtTokenService.generateAccessToken(username, registrationId);
                setAccessTokenCookie(response, newAccess);

                return TokenResponse.builder()
                        .accessToken(newAccess)
                        .refreshToken(refreshTokenValue)
                        .provider(registrationId.toUpperCase())
                        .isLocal("local".equals(registrationId))
                        .build();
            }
        }

        return issueTokenPair(username, registrationId, response);
    }

    @Transactional
    public TokenResponse issueLocalTokenPair(String username, HttpServletResponse response) {
        return issueTokenPair(username, "local", response);
    }

    @Transactional
    public TokenResponse issueTokenPair(String username,
                                        String registrationId,
                                        HttpServletResponse response) {
        String accessToken = jwtTokenService.generateAccessToken(username, registrationId);
        String refreshToken = jwtTokenService.generateRefreshToken(username, registrationId);
        Instant now = Instant.now();

        setAccessTokenCookie(response, accessToken);
        setRefreshTokenCookie(response, refreshToken);

        OAuth2AuthorizedClientEntity entity = authorizedClientRepository
                .findByClientRegistrationIdAndPrincipalName(registrationId, username)
                .orElse(OAuth2AuthorizedClientEntity.builder()
                        .clientRegistrationId(registrationId)
                        .principalName(username)
                        .build());

        entity.setRefreshTokenValue(refreshToken);
        entity.setRefreshTokenIssuedAt(now);
        entity.setRefreshTokenExpiresAt(now.plusMillis(refreshTokenExpirationMs));
        authorizedClientRepository.save(entity);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .provider(registrationId.toUpperCase())
                .isLocal("local".equals(registrationId))
                .build();
    }

    /**
     * Определяет registrationId из authentication.
     * <p>
     * Приоритет:
     * 1. details (String) — выставляется JwtAuthenticationFilter из claim "provider"
     * 2. тип principal — для первого запроса после OAuth2-логина (до того как фильтр
     * прочитал наш JWT)
     * 3. fallback → "local"
     */
    private String resolveRegistrationId(Authentication authentication) {
        // 1. Из JWT claim через JwtAuthenticationFilter
        Object details = authentication.getDetails();
        if (details instanceof String provider && !provider.isBlank()) {
            return provider;
        }

        // 2. Из типа principal (первый запрос сразу после OAuth2-логина)
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUserPrincipal) {
            return "google";
        }
        if (principal instanceof OAuth2UserPrincipal oauth2User) {
            return resolveProviderName(oauth2User.getUserEntity().getProvider());
        }

        // 3. fallback
        return "local";
    }

    private void setAccessTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("access_token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(900);
        response.addCookie(cookie);
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("refresh_token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) (refreshTokenExpirationMs / 1000));
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
            case YANDEX -> "yandex";
            default -> throw new IllegalArgumentException("Not an OAuth2 provider: " + provider);
        };
    }
}