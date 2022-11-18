package io.scalecube.security.jwt;

import com.auth0.jwt.interfaces.JWTVerifier;

import io.scalecube.security.api.Profile;
import reactor.core.publisher.Mono;

public final class DefaultJwtAuthenticator implements JwtAuthenticator {

  private final JWTVerifier verifier;

  public DefaultJwtAuthenticator(JWTVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  public Mono<Profile> authenticate(String token) {
    return Mono.defer(() -> authenticate0(token)).onErrorMap(AuthenticationException::new);
  }

  private Mono<Profile> authenticate0(String token) {
    var tokenWithoutSignature = token.substring(0, token.lastIndexOf(".") + 1);
    return Mono.fromRunnable(() -> this.verifier.verify(tokenWithoutSignature));    
  }
}
