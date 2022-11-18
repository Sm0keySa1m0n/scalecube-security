module io.scalecube.security {

  exports io.scalecube.security.api;
  exports io.scalecube.security.jwt;

  requires reactor.core;
  requires org.reactivestreams;
  requires transitive com.auth0.jwt;
}
