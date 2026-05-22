package org.legend8883.oidc_accesstoken.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.token.domain.TokenFacadeService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class LocalLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenFacadeService tokenFacadeService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        tokenFacadeService.issueLocalTokenPair(authentication.getName(), response);
        log.info("Local login: issued JWT for user={}", authentication.getName());
        getRedirectStrategy().sendRedirect(request, response, "/token");
    }
}
