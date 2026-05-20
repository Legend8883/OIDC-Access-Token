package org.legend8883.oidc_accesstoken.auth.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.user.db.entities.UserEntity;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;
import org.legend8883.oidc_accesstoken.user.domain.UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {

    private final UserService userService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String providerId = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName() != null ? oidcUser.getFullName() : email;

        log.info("OIDC login via Google: sub={}, email={}", providerId, email);

        UserEntity userEntity = userService.findOrCreateOAuth2User(
                AuthProvider.GOOGLE, providerId, name, email);

        // Достаём access token из userRequest - он есть прямо здесь при логине
        String accessToken = userRequest.getAccessToken().getTokenValue();

        return new OidcUserPrincipal(oidcUser, userEntity, accessToken);
    }
}
