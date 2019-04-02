package io.github.grantchan.ssh.util.key.deserializer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

public class DSAKeyPairDeserializer implements KeyPairDeserializer {

  private static final String BEGIN_LINE = "-----BEGIN DSA PRIVATE KEY-----";
  private static final String END_LINE = "-----END DSA PRIVATE KEY-----";

  private static final DSAKeyPairDeserializer instance = new DSAKeyPairDeserializer();

  public static KeyPairDeserializer getInstance() {
    return instance;
  }

  @Override
  public String getBeginLine() {
    return BEGIN_LINE;
  }

  @Override
  public String getEndLine() {
    return END_LINE;
  }

  @Override
  public KeyPair unmarshal(byte[] bytes) throws IOException, GeneralSecurityException {
    return null;
  }
}
