package io.scalecube.security.acl;

public class AuthorizationException extends Exception {

  private static final long serialVersionUID = -5659327331930625115L;

  public AuthorizationException(String message) {
    super(message);
  }
}
