package io.github.grantchan.ssh.common.transport.kex;

import io.github.grantchan.ssh.util.buffer.Bytes;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Objects;

public class ECDH extends KeyExchange {

  private ECParameterSpec spec;

  public ECDH(final ECurve curve) {
    this(Objects.requireNonNull(curve).value());
  }

  public ECDH(final ECParameterSpec spec) {
    Objects.requireNonNull(spec);

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(spec);
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      e.printStackTrace();
      return;
    }

    this.spec = spec;

    KeyPair kp = kpg.generateKeyPair();
    ECPoint pt = ((ECPublicKey)kp.getPublic()).getW();
    this.pubKey = toBytes(pt, spec.getCurve());

    try {
      this.ka = KeyAgreement.getInstance("ECDH");
      this.ka.init(kp.getPrivate());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  @Override
  public String getName() {
    return "EC";
  }

  @Override
  KeySpec getKeySpec() {
    return new ECPublicKeySpec(toECPoint(receivedPubKey), spec);
  }

  /**
   * Converts an ECPoint to a byte array
   *
   * @see <a href="http://www.secg.org/sec1-v2.pdf">Elliptic Curve Cryptography</a>
   */
  public static byte[] toBytes(final ECPoint pt, final EllipticCurve curve) {
    int mlen = (Objects.requireNonNull(curve).getField().getFieldSize() + 7) / 8;

    byte[] x = Objects.requireNonNull(pt).getAffineX().toByteArray();
    if (x.length != mlen) {
      int i = 0;
      while (i < x.length && x[i] == 0) {
        i++;
      }

      int range = x.length - i;
      if (range == 0 || range > mlen) {  // all zeroes or exceeded?
        throw new IllegalArgumentException("Illegal X coordinate of elliptic curve point , length: "
                                           + x.length + " is too long");
      }
      byte[] t = new byte[mlen];
      System.arraycopy(x, i, t, mlen - range, range);
      x = t;
    }

    byte[] y = pt.getAffineY().toByteArray();
    if (y.length != mlen) {
      int i = 0;
      while (i < y.length && y[i] == 0) {
        i++;
      }

      int range = y.length - i;
      if (range == 0 || range > mlen) {  // all zeroes or exceeded?
        throw new IllegalArgumentException("Illegal Y coordinate of elliptic curve point , length: "
                                           + y.length + " is too long");
      }
      byte[] t = new byte[mlen];
      System.arraycopy(y, i, t, mlen - range, range);
      y = t;
    }

    return Bytes.concat(new byte[]{0x04}, x, y);
  }

  /**
   * Converts a byte array to an ECPoint
   */
  private static ECPoint toECPoint(final byte[] buf) {
    Objects.requireNonNull(buf);

    int i = 0;
    while (i < buf.length && buf[i] == 0) {
      i++;
    }

    if (i == buf.length) {  // when it reach the end, means all zeroes
      throw new IllegalArgumentException("Invalid ECPoint data - contains all zeroes");
    }

    if (buf[i] != 0x04) {
      if (buf[i] == 0x02 || buf[i] == 0x03) {
        throw new NotImplementedException();  // only support uncompress data
      } else {
        throw new IllegalArgumentException("Unknown ECPoint data compression: " + buf[i]);
      }
    }

    i++;
    int len = buf.length - i;
    if ((len & 0x01L) == 1) {
      throw new IllegalArgumentException("Invalid ECPoint data - X and Y aren't presented in" +
                                         " equal length");
    }

    int mlen = len >> 1;
    byte[] x = Arrays.copyOfRange(buf, i, i + mlen);
    byte[] y = Arrays.copyOfRange(buf, i + mlen, i + len);

    return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
  }
}
