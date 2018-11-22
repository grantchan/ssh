package io.github.grantchan.ssh.trans.signature;

import java.security.Key;
import java.security.SignatureException;
import java.util.Objects;

public class DSASignature extends Signature {

  public DSASignature(Key key) {
    this("SHA1withDSA", key);
  }

  public DSASignature(String transformation, Key key) {
    super(transformation, key);
  }

  @Override
  public boolean verify(byte[] data) throws SignatureException {
    return Objects.requireNonNull(instance).verify(data);
  }
}
