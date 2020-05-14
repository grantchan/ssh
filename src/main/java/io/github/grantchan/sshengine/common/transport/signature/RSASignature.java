package io.github.grantchan.sshengine.common.transport.signature;

import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
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
        RSAKey rsa = (RSAKey) key;
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
      throw new SignatureException("Empty signature data");
    }

    /*
     * The resulting signature is encoded as follows:
     *
     * string    "ssh-rsa"
     * string    rsa_signature_blob
     *
     * The value for 'rsa_signature_blob' is encoded as a string containing s
     * (which is an integer, without lengths or padding, unsigned, and in
     * network byte order).
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-6.6">Public Key Algorithms</a>
     */
    ByteBuf buf = Unpooled.wrappedBuffer(sig);
    String keyType = ByteBufIo.readUtf8(buf);
    if (!keyType.equals("ssh-rsa")) {
      throw new IllegalArgumentException("Key type mismatched, expected: ssh-rsa, actual: " +
          keyType);
    }

    byte[] sigData = ByteBufIo.readBytes(buf);

    if (sigData.length < signatureSize) {
      // if not enough signature data, fill with zero padding at the beginning
      byte[] padding = new byte[signatureSize];
      System.arraycopy(sigData, 0, padding, padding.length - sigData.length, sigData.length);
      sigData = padding;
    }

    return Objects.requireNonNull(instance).verify(sigData);
  }
}
