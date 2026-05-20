package org.legend8883.oidc_accesstoken.token.db.repositories;

import org.legend8883.oidc_accesstoken.token.db.entities.OAuth2AuthorizedClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizedClientRepository extends JpaRepository<OAuth2AuthorizedClientEntity, Long> {

    Optional<OAuth2AuthorizedClientEntity> findByClientRegistrationIdAndPrincipalName(
            String clientRegistrationId, String principalName);

    @Modifying
    @Query("DELETE FROM OAuth2AuthorizedClientEntity e WHERE e.clientRegistrationId = :clientRegistrationId AND e.principalName = :principalName")
    void deleteByClientRegistrationIdAndPrincipalName(String clientRegistrationId, String principalName);
}
