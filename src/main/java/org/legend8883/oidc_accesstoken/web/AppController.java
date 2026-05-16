package org.legend8883.oidc_accesstoken.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.auth.local.dto.RegistrationRequest;
import org.legend8883.oidc_accesstoken.token.api.dto.TokenResponse;
import org.legend8883.oidc_accesstoken.token.domain.TokenFacadeService;
import org.legend8883.oidc_accesstoken.user.domain.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AppController {

    private final UserService userService;
    private final TokenFacadeService tokenFacadeService;

    // ── Home ──────────────────────────────────────────────────────────────────

    @GetMapping("/")
    public String home(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/token";
        }
        return "index";
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @GetMapping("/login")
    public String loginPage(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/token";
        }
        return "login";
    }

    // ── Registration ──────────────────────────────────────────────────────────

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

    // ── Token page ────────────────────────────────────────────────────────────

    @GetMapping("/token")
    public String tokenPage(Authentication authentication, HttpSession session, Model model) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        TokenResponse tokens = tokenFacadeService.resolveTokens(authentication, session);
        model.addAttribute("tokens", tokens);
        model.addAttribute("username", authentication.getName());
        return "token";
    }

    @PostMapping("/token/refresh")
    public String refreshToken(Authentication authentication, HttpSession session,
                               RedirectAttributes redirectAttributes) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        TokenResponse tokens = tokenFacadeService.refreshTokens(authentication, session);
        redirectAttributes.addFlashAttribute("refreshed", true);
        redirectAttributes.addFlashAttribute("tokens", tokens);
        return "redirect:/token";
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        request.getSession().invalidate();
        return "redirect:/login?logout";
    }
}
