package org.legend8883.oidc_accesstoken.token.db;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(
        name = "oauth2_authorized_client",
        uniqueConstraints = @UniqueConstraint(columnNames = {"client_registration_id", "principal_name"})
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2AuthorizedClientEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_registration_id", length = 100, nullable = false)
    private String clientRegistrationId;

    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;

    @Column(name = "access_token_type", length = 100, nullable = false)
    private String accessTokenType;

    @Column(name = "access_token_value", columnDefinition = "TEXT", nullable = false)
    private String accessTokenValue;

    @Column(name = "access_token_issued_at", nullable = false)
    private Instant accessTokenIssuedAt;

    @Column(name = "access_token_expires_at", nullable = false)
    private Instant accessTokenExpiresAt;

    @Column(name = "access_token_scopes", length = 1000)
    private String accessTokenScopes;

    @Column(name = "refresh_token_value", columnDefinition = "TEXT")
    private String refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
