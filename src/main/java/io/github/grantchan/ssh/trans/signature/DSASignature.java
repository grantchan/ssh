package io.github.grantchan.ssh.trans.signature;

import com.sun.xml.internal.txw2.IllegalSignatureException;
import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
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
      String keyType = ByteBufUtil.readUtf8(buf);
      if (!keyType.equals("ssh-dss")) {
        throw new IllegalArgumentException("Key type mismatched, expected: ssh-dss, actual: " +
            keyType);
      }

      sig = ByteBufUtil.readBytes(buf);
      if (sig.length != DSA_SIGNATURE_LENGTH) {
        throw new SignatureException("Invalid signature length, expected: " + DSA_SIGNATURE_LENGTH +
            ", actual: " + sig.length);
      }
    }

    int i = 0;
    while (sig[i] == 0 && ((sig[i+1] & 0x80) == 0) && i < BLOB_STRING_LENGTH - 1) {
      i++;
    }
    int rLen = BLOB_STRING_LENGTH - i;  // length of R
//
//    byte[] r = new byte[rLen];
//    r[0] = 0x02;
//
//    System.arraycopy(sig, i, r, 1, rLen - 1);
//
//    i = BLOB_STRING_LENGTH;
//    while (sig[i] == 0 && i < (BLOB_STRING_LENGTH << 1)) {
//      i++;
//    }
//    int sLen = (BLOB_STRING_LENGTH << 1) - i + 1;
//    byte[] s = new byte[sLen];
//    s[0] = 0;
//    System.arraycopy(sig, i, s, 1, sLen - 1);

    return Objects.requireNonNull(instance).verify(sig);
  }
}
