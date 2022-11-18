package io.scalecube.security.jwt;

import java.util.Map;
import java.util.stream.Stream;

public interface Claims {

  <T> T get(String name, Class<T> type);

  Stream<Map.Entry<String, Object>> stream();
}
