package org.legend8883.oidc_accesstoken.config;

import lombok.RequiredArgsConstructor;
import org.legend8883.oidc_accesstoken.auth.local.LocalUserDetailsService;
import org.legend8883.oidc_accesstoken.auth.oauth2.CustomOAuth2UserService;
import org.legend8883.oidc_accesstoken.auth.oauth2.CustomOidcUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final LocalUserDetailsService localUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(localUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/register", "/css/**", "/js/**", "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/token", true)
                        .failureUrl("/login?error")
                        .permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/token", true)
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(customOidcUserService)
                                .userService(customOAuth2UserService)))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID"));

        return http.build();
    }
}