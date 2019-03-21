package io.github.grantchan.ssh.util.key.deserializer;

import java.security.KeyPair;
import java.util.Collection;
import java.util.List;

public class RSAKeyPairDeserializer implements KeyPairDeserializer {

  private static final RSAKeyPairDeserializer instance = new RSAKeyPairDeserializer();
  public static KeyPairDeserializer getInstance() {
    return instance;
  }

  @Override
  public String getType() {
    return "RSA";
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
