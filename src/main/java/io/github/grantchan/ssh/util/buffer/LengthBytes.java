package io.github.grantchan.ssh.util.buffer;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class LengthBytes {

  private byte[] value;

  public LengthBytes() {

  }

  public LengthBytes(byte[] ... raws) {
    value = concat(raws);
  }

  public LengthBytes append(byte[] ... raws) {
    value = Bytes.concat(value, concat(raws));

    return this;
  }

  public LengthBytes append(boolean ... bs) {
    value = Bytes.concat(value, concat(bs));
    return this;
  }

  public LengthBytes append(int ... is) {
    value = Bytes.concat(value, concat(is));

    return this;
  }

  public LengthBytes append(BigInteger ... bis) {
    value = Bytes.concat(value, concat(bis));

    return this;
  }

  public byte[] toBytes() {
    return value;
  }

  @Override
  public String toString() {
    return Arrays.toString(value);
  }

  /**
   * Concatenate length byte arrays
   *
   * @param bufs Byte arrays to concatenate, from left to right
   * @return the new constructed length byte array with its value being the concatenation of
   * {@param bufs}
   */
  public static byte[] concat(byte[] ... bufs) {
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

  public static byte[] concat(boolean ... bs) {
    if (bs == null) {
      return null;
    }

    byte[] res = new byte[bs.length];
    for (int i = 0; i < res.length; i++) {
      res[i] = bs[i] ? (byte) 1 : (byte) 0;
    }

    return res;
  }

  public static byte[] concat(int ... nums) {
    if (nums == null) {
      return null;
    }

    byte[] res = null;
    for (int n : nums) {
      res = Bytes.concat(res, Bytes.htonl(n));
    }

    return res;
  }

  public static byte[] concat(String ... vals) {
    if (vals == null) {
      return null;
    }

    List<byte[]> bufs = new ArrayList<>(vals.length);

    int size = 0;
    for (String s : vals) {
      if (s != null) {
        size += Integer.BYTES + s.length();
        bufs.add(s.getBytes(StandardCharsets.UTF_8));
      }
    }

    if (size == 0) {
      return null;
    }

    byte[] res = new byte[size];
    int off = 0;
    for (byte[] buf : bufs) {
      byte[] len = Bytes.htonl(buf.length);
      System.arraycopy(len, 0, res, off, len.length);
      off += len.length;

      System.arraycopy(buf, 0, res, off, buf.length);
      off += buf.length;
    }

    return res;
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

}
