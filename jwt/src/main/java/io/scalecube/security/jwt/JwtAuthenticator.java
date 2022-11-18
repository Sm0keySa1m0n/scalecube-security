package io.scalecube.security.jwt;

import java.util.Map;
import java.util.stream.Collectors;
import io.scalecube.security.api.Authenticator;
import io.scalecube.security.api.Profile;
import reactor.core.publisher.Mono;

public interface JwtAuthenticator extends Authenticator {

  /**
   * Authenticate a JWT token.
   *
   * @param token jwt token.
   * @return security profile.
   */
  @Override
  Mono<Profile> authenticate(String token);

  /**
   * Create a profile from claims.
   *
   * @param payload the claims to parse
   * @return a profile from the claims
   */
  default Profile profileFromClaims(Claims claims) {
    return Profile.builder()
        .userId(claims.get("sub", String.class))
        .tenant(claims.get("aud", String.class))
        .email(claims.get("email", String.class))
        .emailVerified(claims.get("email_verified", Boolean.class))
        .name(claims.get("name", String.class))
        .familyName(claims.get("family_name", String.class))
        .givenName(claims.get("given_name", String.class))
        .claims(claims.stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)))
        .build();
  }
}
