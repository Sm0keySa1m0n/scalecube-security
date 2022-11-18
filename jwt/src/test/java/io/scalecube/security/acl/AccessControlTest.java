package io.scalecube.security.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.scalecube.security.acl.DefaultAccessControl;
import io.scalecube.security.api.Authenticator;
import io.scalecube.security.jwt.DefaultJwtAuthenticator;
import reactor.test.StepVerifier;

class AccessControlTest {

  // user permissions
  private static final String RESOURCE_READ = "resource/read";
  private static final String RESOURCE_CREATE = "resource/create";
  private static final String RESOURCE_DELETE = "resource/delete";

  // user roles
  private static final String OWNER = "owner";
  private static final String ADMIN = "admin";
  private static final String MEMBER = "member";

  private static SecretKey key;
  private static DefaultAccessControl accessControl;

  @BeforeAll
  static void setUp() throws Exception {
    key = KeyGenerator.getInstance("HmacSHA256").generateKey();

    Authenticator authenticator =
        new DefaultJwtAuthenticator(JWT.require(Algorithm.HMAC256(key.getEncoded()))
                .build());

    accessControl =
        DefaultAccessControl.builder()
            .authenticator(authenticator)
            .authorizer(
                Permissions.builder()
                    .grant(RESOURCE_DELETE, OWNER)
                    .grant(RESOURCE_CREATE, OWNER, ADMIN)
                    .grant(RESOURCE_READ, OWNER, ADMIN, MEMBER)
                    .build())
            .build();
  }

  @Test
  void shouldGrantAccess() throws NoSuchAlgorithmException {

    String token =
        JWT.create().withClaim("roles", OWNER).sign(Algorithm.HMAC256(key.getEncoded()));

    StepVerifier.create(accessControl.check(token, RESOURCE_CREATE))
        .assertNext(
            profile -> {
              assertEquals(profile.claim("roles"), OWNER);
            })
        .verifyComplete();
  }

  @Test
  void shouldDenyAccess() throws NoSuchAlgorithmException {

    String token =
         JWT.create().withClaim("roles", MEMBER).sign(Algorithm.HMAC256(key.getEncoded()));

    StepVerifier.create(accessControl.check(token, RESOURCE_DELETE))
        .expectError(AuthorizationException.class)
        .verify();
  }
}
