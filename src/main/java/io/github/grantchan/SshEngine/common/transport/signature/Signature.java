package io.github.grantchan.SshEngine.common.transport.signature;

import io.netty.buffer.ByteBuf;

import java.security.*;
import java.util.Objects;

public abstract class Signature {

  protected java.security.Signature instance;

  public Signature(String transformation, Key key) {
    try {
      instance = java.security.Signature.getInstance(transformation);
      if (key instanceof PublicKey) {
        instance.initVerify((PublicKey) key);
      } else if (key instanceof PrivateKey) {
        instance.initSign((PrivateKey) key);
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  public void update(byte[] data) throws SignatureException {
    Objects.requireNonNull(instance).update(data);
  }

  public void update(ByteBuf data) throws SignatureException {
    byte[] bytes = new byte[data.readableBytes()];
    data.readBytes(bytes);

    update(bytes);
  }

  public final byte[] sign() throws SignatureException {
    return Objects.requireNonNull(instance).sign();
  }

  public abstract boolean verify(byte[] data) throws SignatureException;
}
