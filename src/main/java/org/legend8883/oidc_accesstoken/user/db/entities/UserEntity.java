package org.legend8883.oidc_accesstoken.user.db.entities;

import jakarta.persistence.*;
import lombok.*;
import org.legend8883.oidc_accesstoken.user.db.enums.AuthProvider;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    private String password;

    private String email;

    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    private String providerId;
}
