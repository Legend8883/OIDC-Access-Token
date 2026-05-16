package org.legend8883.oidc_accesstoken.user.domain;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.legend8883.oidc_accesstoken.user.db.entities.UserEntity;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;
import org.legend8883.oidc_accesstoken.user.db.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserEntity findOrCreateOAuth2User(AuthProvider provider, String providerId,
                                             String username, String email) {
        return userRepository.findByProviderAndProviderId(provider, providerId)
                .orElseGet(() -> {
                    String uniqueUsername = resolveUniqueUsername(username);
                    UserEntity user = UserEntity.builder()
                            .username(uniqueUsername)
                            .email(email)
                            .provider(provider)
                            .providerId(providerId)
                            .build();
                    log.info("Creating new OAuth2 user: {} via {}", uniqueUsername, provider);
                    return userRepository.save(user);
                });
    }

    @Transactional
    public UserEntity registerLocalUser(String username, String rawPassword, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken: " + username);
        }
        UserEntity user = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(rawPassword))
                .email(email)
                .provider(AuthProvider.LOCAL)
                .build();
        log.info("Registering local user: {}", username);
        return userRepository.save(user);
    }

    public UserEntity findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }

    private String resolveUniqueUsername(String base) {
        String candidate = base;
        int suffix = 1;
        while (userRepository.existsByUsername(candidate)) {
            candidate = base + "_" + suffix++;
        }
        return candidate;
    }
}
