package io.scalecube.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import io.scalecube.security.jwt.DefaultJwtAuthenticator;
import io.scalecube.security.jwt.JwtAuthenticator;
import reactor.test.StepVerifier;

class JwtAuthenticatorTests {

  private static final Algorithm hmacSecretKey =
      Algorithm.HMAC256(UUID.randomUUID().toString().getBytes());

  @Test
  void authenticateCreateTokenAndAuthenticateHmacAuthenticationSuccess() {
    String token =
        JWT.create()
            .withAudience("Tenant1")
            .withSubject("1")
            .withClaim("name", "Trader1")
            .sign(hmacSecretKey);

    JwtAuthenticator sut = new DefaultJwtAuthenticator(JWT.require(hmacSecretKey).build());

    StepVerifier.create(sut.authenticate(token))
        .assertNext(
            profile -> {
              assertEquals("Tenant1", profile.tenant());
              assertEquals("Trader1", profile.name());
              assertEquals("1", profile.userId());
            })
        .verifyComplete();
  }

  @Test
  void authenticateMissingClaimsInTokenAuthenticationSuccessProfilePropertyIsMissing() {
    String token =
        JWT.create()
            .withAudience("Tenant1")
            .withSubject("1")
            .sign(hmacSecretKey);

    JwtAuthenticator sut = new DefaultJwtAuthenticator(JWT.require(hmacSecretKey).build());

    StepVerifier.create(sut.authenticate(token))
        .assertNext(
            profile -> {
              assertEquals("Tenant1", profile.tenant());
              assertNull(profile.name());
              assertEquals("1", profile.userId());
            })
        .verifyComplete();
  }

  @Test
  void authenticateUnsignedTokenAuthenticationFailsExceptionThrown() {
    var token = JWT.create().withAudience("Tenant1").withSubject("1").sign(Algorithm.none());

    JwtAuthenticator sut =
        new DefaultJwtAuthenticator(JWT.require(hmacSecretKey).build());

    StepVerifier.create(sut.authenticate(token))
        .expectErrorSatisfies(
            actualException ->
                assertEquals(AlgorithmMismatchException.class, actualException.getCause().getClass()));
  }

  @Test
  void authenticateAuthenticateExpiredTokenFails() {
    String token =
        JWT.create()
            .withAudience("Tenant1")
            .withSubject("1")
            .withExpiresAt(Instant.ofEpochMilli(0))
            .withClaim("name", "Trader1")
            .sign(hmacSecretKey);

    JwtAuthenticator sut = new DefaultJwtAuthenticator(JWT.require(hmacSecretKey).build());
    StepVerifier.create(sut.authenticate(token))
        .expectErrorSatisfies(
            actualException ->
                assertEquals(TokenExpiredException.class, actualException.getCause().getClass()));
  }
}
