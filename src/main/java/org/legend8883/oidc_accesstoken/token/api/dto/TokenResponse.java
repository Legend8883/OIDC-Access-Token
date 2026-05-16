package org.legend8883.oidc_accesstoken.token.api.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TokenResponse {
    private final String accessToken;
    private final String refreshToken;
    private final String provider;
    private final boolean isLocal;
}
