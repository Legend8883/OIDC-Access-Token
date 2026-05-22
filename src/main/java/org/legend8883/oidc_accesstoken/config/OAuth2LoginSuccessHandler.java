package org.legend8883.oidc_accesstoken.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.auth.oauth2.OAuth2UserPrincipal;
import org.legend8883.oidc_accesstoken.auth.oauth2.OidcUserPrincipal;
import org.legend8883.oidc_accesstoken.token.domain.TokenFacadeService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenFacadeService tokenFacadeService;

    public OAuth2LoginSuccessHandler(TokenFacadeService tokenFacadeService) {
        super("/token");
        this.tokenFacadeService = tokenFacadeService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        Object principal = authentication.getPrincipal();

        String username;
        String registrationId;

        if (principal instanceof OidcUserPrincipal oidcUser) {
            username = oidcUser.getUserEntity().getUsername();
            registrationId = "google";
        } else if (principal instanceof OAuth2UserPrincipal oauth2User) {
            username = oauth2User.getUserEntity().getUsername();
            registrationId = oauth2User.getUserEntity().getProvider().name().toLowerCase();
        } else {
            getRedirectStrategy().sendRedirect(request, response, "/token");
            return;
        }

        // issueTokenPair сам сохраняет токены в БД с правильным registrationId
        tokenFacadeService.issueTokenPair(username, registrationId, response);

        log.info("OAuth2 login: issued JWT for user={}, provider={}", username, registrationId);
        getRedirectStrategy().sendRedirect(request, response, "/token");
    }
}
