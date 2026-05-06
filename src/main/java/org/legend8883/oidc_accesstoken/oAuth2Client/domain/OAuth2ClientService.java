package org.legend8883.oidc_accesstoken.oAuth2Client.domain;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

@Service
@RequiredArgsConstructor
public class OAuth2ClientService {
    private final OAuth2AuthorizedClientService authorizedClientService;

    public String getAccessToken(
            OAuth2AuthenticationToken authenticationToken,
            Model model
    ) {
        if (authenticationToken == null) {
            return "redirect:/";
        }

        String clientRegistrationId = authenticationToken.getAuthorizedClientRegistrationId();
        String userName = authenticationToken.getName();

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(clientRegistrationId, userName);

        String accessToken = (authorizedClient != null)
                ? authorizedClient.getAccessToken().getTokenValue()
                : "Not found authorized client. Maybe token already expired";

        model.addAttribute("accessToken", accessToken);
        return "token";
    }
}
