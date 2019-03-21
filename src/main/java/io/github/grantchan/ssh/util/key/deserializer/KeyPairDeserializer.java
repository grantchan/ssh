package io.github.grantchan.ssh.util.key.deserializer;

import java.security.KeyPair;
import java.util.Collection;
import java.util.List;

public interface KeyPairDeserializer {

  String getType();

  boolean support(List<String> lines);

  Collection<KeyPair> unmarshal(List<String> lines);
}
