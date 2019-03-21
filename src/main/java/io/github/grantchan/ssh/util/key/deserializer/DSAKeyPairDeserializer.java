package io.github.grantchan.ssh.util.key.deserializer;

import java.security.KeyPair;
import java.util.Collection;
import java.util.List;

public class DSAKeyPairDeserializer implements KeyPairDeserializer {

  private static final DSAKeyPairDeserializer instance = new DSAKeyPairDeserializer();
  public static KeyPairDeserializer getInstance() {
    return instance;
  }

  @Override
  public String getType() {
    return "DSA";
  }

  @Override
  public boolean support(List<String> lines) {
    return false;
  }

  @Override
  public Collection<KeyPair> unmarshal(List<String> lines) {
    return null;
  }
}
