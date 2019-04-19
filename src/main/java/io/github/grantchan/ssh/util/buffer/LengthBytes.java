package io.github.grantchan.ssh.util.buffer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public final class LengthBytes {

  /**
   * Concatenate length byte arrays
   * @param bufs Byte arrays to concatenate, from left to right
   * @return the new constructed length byte array with its value being the concatenation of
   * {@param bufs}
   */
  public static byte[] concat(final byte[] ... bufs) {
    if (bufs == null) {
      return null;
    }

    int size = 0;
    for (byte[] buf : bufs) {
      if (buf != null) {
        size += Integer.BYTES + buf.length;
      }
    }

    if (size == 0) {
      return null;
    }

    byte[] res = new byte[size];
    int off = 0;
    for (byte[] buf : bufs) {
      if (buf != null) {
        // write buffer size
        byte[] len = Bytes.htonl(buf.length);
        System.arraycopy(len, 0, res, off, len.length);
        off += len.length;

        // write buffer
        System.arraycopy(buf, 0, res, off, buf.length);
        off += buf.length;
      }
    }

    return res;
  }

  public static byte[] concat(final boolean ... data) {
    return null;
  }

  public static byte[] concat(final int ... data) {
    return null;
  }

  public static byte[] concat(final String ... data) {
    return null;
  }

  /**
   *
   * @param nums
   * @return
   */
  public static byte[] concat(final BigInteger ... nums) {
    if (nums == null) {
      return null;
    }

    List<byte[]> bufs = new ArrayList<>(nums.length);

    int size = 0;
    for (BigInteger num : nums) {
      if (num != null) {
        byte[] buf = num.toByteArray();
        if ((buf[0] & 0x80) != 0) {
          size += Integer.BYTES + Byte.BYTES + buf.length;
        } else {
          size += Integer.BYTES + buf.length;
        }

        bufs.add(buf);
      }
    }

    if (size == 0) {
      return null;
    }

    byte[] res = new byte[size];
    int off = 0;
    for (byte[] buf : bufs) {
      // write buffer size
      if ((buf[0] & 0x80) != 0) {
        byte[] len = Bytes.htonl(buf.length + 1);
        System.arraycopy(len, 0, res, off, len.length);
        off += len.length;

        byte[] pad = {0};
        System.arraycopy(pad, 0, res, off, pad.length);
        off += pad.length;
      } else {
        byte[] len = Bytes.htonl(buf.length);
        System.arraycopy(len, 0, res, off, len.length);
        off += len.length;
      }

      // write buffer
      System.arraycopy(buf, 0, res, off, buf.length);
      off += buf.length;
    }

    return res;
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private LengthBytes() {}
}
