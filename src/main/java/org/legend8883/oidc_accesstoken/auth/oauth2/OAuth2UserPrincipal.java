package org.legend8883.oidc_accesstoken.auth.oauth2;

import lombok.Getter;
import org.legend8883.oidc_accesstoken.user.db.entities.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class OAuth2UserPrincipal implements OAuth2User {

    private final OAuth2User delegate;
    private final UserEntity userEntity;

    public OAuth2UserPrincipal(OAuth2User delegate, UserEntity userEntity) {
        this.delegate = delegate;
        this.userEntity = userEntity;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return delegate.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getName() {
        return userEntity.getUsername();
    }
}
