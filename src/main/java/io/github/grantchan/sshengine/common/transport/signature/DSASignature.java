package io.github.grantchan.sshengine.common.transport.signature;

import com.sun.xml.internal.txw2.IllegalSignatureException;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.security.Key;
import java.security.SignatureException;
import java.util.Objects;

public class DSASignature extends Signature {

  private final int DSA_SIGNATURE_LENGTH = 40;
  private final int BLOB_STRING_LENGTH = 20;

  public DSASignature(Key key) {
    this("SHA1withDSA", key);
  }

  public DSASignature(String transformation, Key key) {
    super(transformation, key);
  }

  @Override
  public boolean verify(byte[] sig) throws SignatureException {
    if (sig == null) {
      throw new IllegalSignatureException("Empty signature data");
    }

    /*
     * The resulting signature is encoded as follows:
     *
     * string    "ssh-dss"
     * string    dss_signature_blob
     *
     * The value for 'dss_signature_blob' is encoded as a string containing r,
     * followed by s (which are 160-bit integers, without lengths or padding,
     * unsigned, and in network byte order).
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-6.6">Public Key Algorithms</a>
     */
    if (sig.length != DSA_SIGNATURE_LENGTH) {
      ByteBuf buf = Unpooled.wrappedBuffer(sig);
      String keyType = ByteBufIo.readUtf8(buf);
      if (!keyType.equals("ssh-dss")) {
        throw new IllegalArgumentException("Key type mismatched, expected: ssh-dss, actual: " +
            keyType);
      }

      sig = ByteBufIo.readBytes(buf);
      if (sig.length != DSA_SIGNATURE_LENGTH) {
        throw new SignatureException("Invalid signature length, expected: " + DSA_SIGNATURE_LENGTH +
            ", actual: " + sig.length);
      }
    }

    byte[] r = encode(sig, 0, BLOB_STRING_LENGTH);
    byte[] s = encode(sig, BLOB_STRING_LENGTH, BLOB_STRING_LENGTH);
    sig = encode(r, s);

    return Objects.requireNonNull(instance).verify(sig);
  }

  /**
   * The whole buffer is formatted as:<br/>
   * 0x02 [actual length of signature] 0x00 [signature trimmed zero in front]
   */
  private byte[] encode(byte[] data, int off, int len) {
    while (len > 0 && data[off] == 0) {
      ++off;
      --len;
    }

    if (len <= 0) {
      throw new IllegalSignatureException("Invalid signature length, length: " + len);
    }

    boolean needPad = (data[off] & 0x80) != 0;

    int totalLen = len;
    if (needPad) {  // if the signature bytes starts with a negative byte value
      ++totalLen;   // we need to pad an extra zero byte in front
    }
    byte[] lenBytes = encode(totalLen);

    byte[] buf = new byte[Byte.BYTES + lenBytes.length + totalLen];
    int cnt = 0;
    buf[cnt++] = 0x02;
    System.arraycopy(lenBytes, 0, buf, cnt, lenBytes.length);
    cnt += lenBytes.length;
    if (needPad) {
      buf[cnt++] = 0; // the exta zero padding mentioned above
    }
    System.arraycopy(data, off, buf, cnt, len);

    return buf;
  }

  private byte[] encode(int i) {
    if (i < 128) {
      return new byte[]{(byte) i};
    }

    byte[] nbo = Bytes.toBigEndian(i);
    int n = 0;
    while (nbo[n] == 0) {
      ++n;
    }
    byte[] buf = new byte[nbo.length - n];
    System.arraycopy(nbo, n, buf, 0, nbo.length - n);

    return buf;
  }

  private byte[] encode(byte[] r, byte[] s) {
    int len = r.length + s.length;
    byte[] lenBytes = encode(len);

    byte[] buf = new byte[Byte.BYTES + lenBytes.length + len];
    int cnt = 0;
    buf[cnt++] = 0x30;
    System.arraycopy(lenBytes, 0, buf, cnt, lenBytes.length);
    cnt += lenBytes.length;
    System.arraycopy(r, 0, buf, cnt, r.length);
    cnt += r.length;
    System.arraycopy(s, 0, buf, cnt, s.length);

    return buf;
  }
}
