package io.github.grantchan.ssh.trans.signature;

import com.sun.xml.internal.txw2.IllegalSignatureException;
import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.math.BigInteger;
import java.security.Key;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;
import java.util.Objects;

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

  @Override
  public boolean verify(byte[] sig) throws SignatureException {
    if (sig == null) {
      throw new IllegalSignatureException("Empty signature data");
    }

    ByteBuf buf = Unpooled.wrappedBuffer(sig);
    String keyType = ByteBufUtil.readUtf8(buf);
    if (!keyType.equals("ssh-rsa")) {
      throw new IllegalArgumentException("Key type mismatched, expected: ssh-rsa, actual: " +
          keyType);
    }

    byte[] sigData = ByteBufUtil.readBytes(buf);

    if (sigData.length < signatureSize) {
      // if not enough signature data, fill with zero padding at the beginning
      byte[] padding = new byte[signatureSize];
      System.arraycopy(sigData, 0, padding, padding.length - sigData.length, sigData.length);
      sigData = padding;
    }

    return Objects.requireNonNull(instance).verify(sigData);
  }
}
