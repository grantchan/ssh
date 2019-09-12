package io.github.grantchan.sshengine.util.buffer;

import io.github.grantchan.sshengine.common.transport.digest.DigestFactories;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public final class Bytes {

  /**
   * Resize the {@param array} to a new size.
   * <p>If the {@param newSize} is smaller than the original {@param array} size, extra bytes will be
   * truncated.<br>
   * If the {@param newSize} is bigger than or equal to the {@param array} size, just return the
   * {@param array}</p>
   *
   * @param array the array to be resized
   * @param newSize new size of the array to be resized to
   * @return a new resized array or the original array.
   */
  public static byte[] resize(byte[] array, int newSize) {
    if (Objects.requireNonNull(array).length > newSize) {
      byte[] tmp = new byte[newSize];
      System.arraycopy(array, 0, tmp, 0, newSize);

      return tmp;
    }
    return array;
  }

  /**
   * Convert the unsigned integer {@param i} from little-endian(host byte order) to big-endian
   * (network byte order) byte array
   *
   * @param i the unsigned integer in host byte order
   * @return the network byte order byte array of {@param i}
   * @see <a href="https://en.wikipedia.org/wiki/Endianness">Endianness</a>
   */
  public static byte[] htonl(long i) {
    byte[] n = new byte[4];
    n[0] = (byte) (i >>> 24);
    n[1] = (byte) (i >>> 16);
    n[2] = (byte) (i >>> 8);
    n[3] = (byte) i;

    return n;
  }

  /**
   * Read a network byte order(big-endian) integer from buffer {@code buf}
   *
   * @param buf  the buffer has the integer in network byte order.
   *             <p><b>Note:</b> When {@code buf} contains more than {@link Integer#BYTES} bytes,
   *             only the first {@link Integer#BYTES} will be used.</p>
   * @return the unsigned {@code long} integer
   * @throws IllegalArgumentException if {@code buf} contains less than {@link Integer#BYTES} bytes
   * @see #nl(byte[], int, int)
   */
  public static long nl(byte[] buf) {
    return nl(buf, 0, buf.length);
  }

  /**
   * Read a network byte order(big-endian) integer from buffer {@param buf}
   *
   * @param buf  the buffer has the integer in network byte order.
   *             <p><b>Note:</b> When {@param buf} contains more than {@link Integer#BYTES} bytes,
   *             only the first {@link Integer#BYTES} will be used.</p>
   * @param off  The offset in {@param buf}
   * @param len  Length of data in {@param buf} to use to read
   * @return the unsigned {@code long} integer
   * @throws IllegalArgumentException if {@code param} contains less than {@link Integer#BYTES} bytes
   */
  private static long nl(byte[] buf, int off, int len) {
    Objects.requireNonNull(buf);

    if (len < Integer.BYTES) {
      throw new IllegalArgumentException("Not enough data to convert to an unsigned integer, " +
          "required: " + Integer.BYTES + ", actual: " + buf.length);
    }

    long n = 0;
    for (int i = 0, sh = Integer.SIZE - Byte.SIZE; i < Integer.BYTES; i++, sh -= Byte.SIZE) {
      n |= (buf[off + i] & 0xFFL) << sh;
    }

    return n;
  }

  /**
   * Concatenate byte arrays
   *
   * @param bufs byte arrays to concatenate, from left to right
   * @return the new constructed byte array with its value being the concatenation of {@param bufs}
   */
  public static byte[] concat(final byte[]... bufs) {
    if (bufs == null) {
      return null;
    }

    // sum up the total length
    int size = 0;
    for (byte[] buf : bufs) {
      if (buf != null) {
        size += buf.length;
      }
    }

    if (size == 0) {
      return null;
    }

    byte[] res = new byte[size];
    int off = 0;
    for (byte[] buf : bufs) {
      if (buf != null) {
        System.arraycopy(buf, 0, res, off, buf.length);
        off += buf.length;
      }
    }

    return res;
  }

  /**
   * Returns the last N bytes of data in {@param buf}
   */
  public static byte[] last(final byte[] buf, int len) {
    if (Objects.requireNonNull(buf).length <= len) {
      return buf;
    }
    if (len <= 0) {
      return null;
    }

    return Arrays.copyOfRange(buf, buf.length - len, buf.length);
  }

  /**
   * Converts a byte array to hexadecimal string
   * @see #hex(byte[], String)
   */
  static String hex(byte[] buf) {
    return hex(buf, ":");
  }

  /**
   * Generate the hexadecimal encoded string for the given byte array {@param buf}, each byte (2
   * characters) is separacted by {@param sep}
   *
   * @param buf Input byte buffer
   * @param sep separactor for each byte
   * @return the hexadecimal string represents the input bytes {@param buf}
   * @see <a href="https://en.wikipedia.org/wiki/Hexadecimal">Hexadecimal</a>
   */
  private static String hex(byte[] buf, String sep) {
    if (buf == null) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < buf.length; i++) {
      byte b = buf[i];
      sb.append(Character.forDigit((b >> 4) & 0xF, 16));
      sb.append(Character.forDigit((b & 0xF), 16));
      if (sep != null && i < buf.length - 1) {
        sb.append(sep);
      }
    }
    return sb.toString();
  }

  /**
   * Generate the unique identifier of byte array for a number of bytes {@param data}
   *
   * @param data Input byte buffer
   * @param md The one-way hash algorithm to use to generate the finger print
   * @return the finger print byte array represents the input bytes {@param data}
   * @see <a href="https://en.wikipedia.org/wiki/Fingerprint_(computing)">Fingerprint (computing)</a>
   */
  private static byte[] fingerPrint(final byte[] data, MessageDigest md) {
    if (data == null) {
      throw new IllegalArgumentException("Invalid parameter - data is null");
    }
    if (md == null) {
      throw new IllegalArgumentException("Invalid parameter - message digest is null");
    }

    md.update(data);

    return md.digest();
  }

  /**
   * Generate the hexadecimal encoded MD5 hash string for the given byte array {@param data}
   *
   * @param data Input byte buffer
   * @return the MD5 hash string represents the input bytes {@param data}
   * @see <a href="https://en.wikipedia.org/wiki/MD5">MD5</a>
   */
  public static String md5(final byte[] data) {
    if (data == null) {
      throw new IllegalArgumentException("Invalid key parameter - key is null");
    }

    return hex(fingerPrint(data, Objects.requireNonNull(DigestFactories.md5.create())));
  }

  /**
   * Generate the hexdecimal encoded SHA256 hash string for the given byte array {@param data}
   *
   * @param data Input byte buffer
   * @return The SHA256 hash string represents the input bytes {@param data}
   * @see <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>
   */
  public static String sha256(final byte[] data) {
    if (data == null) {
      throw new IllegalArgumentException("Invalid key parameter - key is null");
    }

    byte[] buf = fingerPrint(data, Objects.requireNonNull(DigestFactories.sha256.create()));

    Base64.Encoder base64 = Base64.getEncoder();

    return base64.encodeToString(buf).replaceAll("=", "");
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private Bytes() {}
}
