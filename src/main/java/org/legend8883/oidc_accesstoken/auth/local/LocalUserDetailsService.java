package org.legend8883.oidc_accesstoken.auth.local;

import lombok.RequiredArgsConstructor;
import org.legend8883.oidc_accesstoken.user.db.entities.UserEntity;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;
import org.legend8883.oidc_accesstoken.user.db.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LocalUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username)
                .filter(u -> u.getProvider() == AuthProvider.LOCAL)
                .orElseThrow(() -> new UsernameNotFoundException("Local user not found: " + username));
        return new LocalUserDetails(user);
    }
}
