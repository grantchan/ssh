package io.github.grantchan.ssh.trans.signature;

import java.math.BigInteger;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

public class RSASignature extends Signature {

  private int signatureSize = -1;

  public RSASignature(Key key) {
    this("SHA1withRSA", key);
  }

  public RSASignature(String transformation, Key key) {
    super(transformation, key);

    if (key instanceof PublicKey) { // if initiated as a verifier
      if (key instanceof RSAKey) {
        RSAKey rsa = RSAKey.class.cast(key);
        BigInteger modulus = rsa.getModulus();
        signatureSize = (modulus.bitLength() + Byte.SIZE - 1) / Byte.SIZE;
      } else {
        throw new IllegalArgumentException("not a RSA key");
      }
    }
  }
}
