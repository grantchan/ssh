package io.github.grantchan.ssh.trans.signature;

import java.security.*;
import java.util.Objects;

public abstract class Signature {

  protected java.security.Signature instance;

  public Signature(String transformation, Key key) {
    try {
      instance = java.security.Signature.getInstance(transformation);
      if (key instanceof PublicKey) {
        instance.initVerify(PublicKey.class.cast(key));
      } else if (key instanceof PrivateKey) {
        instance.initSign(PrivateKey.class.cast(key));
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  public void update(byte[] data) throws SignatureException {
    Objects.requireNonNull(instance).update(data);
  }

  public final byte[] sign() throws SignatureException {
    return Objects.requireNonNull(instance).sign();
  }

  public boolean verify(byte[] data) throws SignatureException {
    return Objects.requireNonNull(instance).verify(data);
  }
}
