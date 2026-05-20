package org.legend8883.oidc_accesstoken.web;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.auth.local.dto.RegistrationRequest;
import org.legend8883.oidc_accesstoken.token.api.dto.TokenResponse;
import org.legend8883.oidc_accesstoken.token.domain.TokenFacadeService;
import org.legend8883.oidc_accesstoken.user.domain.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Arrays;
import java.util.Map;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AppController {

    private final UserService userService;
    private final TokenFacadeService tokenFacadeService;

    @GetMapping("/")
    public String home(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/token";
        }
        return "index";
    }

    @GetMapping("/login")
    public String loginPage(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/token";
        }
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("registrationRequest", new RegistrationRequest());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute RegistrationRequest request,
                           BindingResult bindingResult,
                           RedirectAttributes redirectAttributes,
                           Model model) {
        if (bindingResult.hasErrors()) {
            return "register";
        }
        try {
            userService.registerLocalUser(request.getUsername(), request.getPassword(), request.getEmail());
            redirectAttributes.addFlashAttribute("successMessage", "Registration successful! Please log in.");
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            return "register";
        }
    }

    @GetMapping("/token")
    public String tokenPage(Authentication authentication,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            Model model) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        TokenResponse tokens = tokenFacadeService.resolveTokens(authentication, request, response);
        model.addAttribute("tokens", tokens);
        model.addAttribute("username", authentication.getName());
        return "token";
    }

    @GetMapping("/token/current-access")
    @ResponseBody
    public ResponseEntity<Map<String, String>> currentAccessToken(HttpServletRequest request) {
        String token = extractCookieValue(request, "access_token");
        if (token == null) {
            return ResponseEntity.ok(Map.of("accessToken", ""));
        }
        return ResponseEntity.ok(Map.of("accessToken", token));
    }

    // Обновление наших собственных JWT токенов (local)
    @PostMapping("/token/refresh")
    public String refreshLocalToken(Authentication authentication,
                                    HttpServletRequest request,
                                    HttpServletResponse response,
                                    RedirectAttributes redirectAttributes) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        TokenResponse tokens = tokenFacadeService.refreshLocalTokens(request, response, authentication);
        redirectAttributes.addFlashAttribute("refreshed", true);
        redirectAttributes.addFlashAttribute("tokens", tokens);
        return "redirect:/token";
    }

    // Обновление access token у стороннего провайдера (Google, Yandex) по refresh token из БД
    @PostMapping("/token/refresh/oauth2")
    public String refreshOAuth2Token(Authentication authentication,
                                     HttpServletResponse response,
                                     RedirectAttributes redirectAttributes) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        TokenResponse tokens = tokenFacadeService.refreshOAuth2Tokens(authentication, response);
        redirectAttributes.addFlashAttribute("refreshed", true);
        redirectAttributes.addFlashAttribute("tokens", tokens);
        return "redirect:/token";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        request.getSession().invalidate();
        return "redirect:/login?logout";
    }

    private String extractCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
