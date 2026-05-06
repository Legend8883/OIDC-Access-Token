package org.legend8883.oidc_accesstoken.oAuth2Client.api;

import lombok.RequiredArgsConstructor;
import org.legend8883.oidc_accesstoken.oAuth2Client.domain.OAuth2ClientService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class OAuth2ClientController {
    private final OAuth2ClientService oAuth2ClientService;

    @GetMapping("/token")
    public String getAccessToken(
            OAuth2AuthenticationToken authenticationToken,
            Model model
    ) {
        return oAuth2ClientService.getAccessToken(authenticationToken, model);
    }

    @GetMapping("/user")
    @ResponseBody
    public String getUser(@AuthenticationPrincipal OAuth2User principal) {
        return "Hello, " + principal.getAttribute("name");
    }
}
