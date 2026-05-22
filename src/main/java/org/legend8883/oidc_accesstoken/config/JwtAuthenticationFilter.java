package org.legend8883.oidc_accesstoken.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.token.domain.JwtTokenService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = extractCookieValue(request, "access_token");

        if (token != null && jwtTokenService.isTokenValid(token)) {
            try {
                var claims = jwtTokenService.parseToken(token);
                if ("access".equals(claims.get("type"))) {
                    String username = claims.getSubject();
                    String provider = claims.get("provider", String.class);

                    var auth = new UsernamePasswordAuthenticationToken(
                            username, null, Collections.emptyList());

                    // Кладём provider в details — TokenFacadeService его прочитает
                    auth.setDetails(provider != null ? provider : "local");

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception e) {
                log.warn("Failed to set authentication from JWT: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}