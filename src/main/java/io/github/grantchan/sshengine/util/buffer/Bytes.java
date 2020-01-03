package io.github.grantchan.sshengine.util.buffer;

import io.github.grantchan.sshengine.common.transport.digest.DigestFactories;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public final class Bytes {

  /**
   * Resize an array.
   *
   * <ul>
   *   <li>If the new size is smaller than original, extra bytes will be truncated.</li>
   *   <li>If the new size is bigger than or equal to original, just return the array.</li>
   * </ul>
   *
   * @param array   The array to be resized
   * @param newSize New size of the array to be resized to
   * @return        A new resized array or the original array.
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
   * Convert an unsigned integer from little-endian(host byte order) to big-endian (network byte
   * order) byte array
   *
   * @param i The unsigned integer in host byte order
   * @return  The network byte order byte array of {@param i}
   *
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
   * Read a network byte order(big-endian) integer from a byte array.
   *
   * <p>Internally, this invokes {@link #nl(byte[], int, int)}</p>
   *
   * @param buf The byte array, has the integer in network byte order, to be read from.
   *            <p>
   *              Note: When {@code buf} contains more than {@link Integer#BYTES} bytes,
   *              only the first {@link Integer#BYTES} will be used.
   *            </p>
   * @return    The unsigned {@code long} integer
   * @throws IllegalArgumentException if {@code buf} contains less than {@link Integer#BYTES} bytes
   *
   * @see #nl(byte[], int, int)
   */
  public static long nl(byte[] buf) {
    return nl(buf, 0, buf.length);
  }

  /**
   * Read a network byte order(big-endian) integer from a byte array.
   *
   * @param buf  the byte array, has the integer in network byte order, to be read from
   *             <p>
   *               Note: When {@param buf} contains more than {@link Integer#BYTES} bytes,
   *               only the first {@link Integer#BYTES} will be used.
   *             </p>
   * @param off  The offset in {@param buf}
   * @param len  Length of data in {@param buf} to use to read
   * @return     The unsigned {@code long} integer
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
   * Concatenate a set of byte arrays.
   *
   * @param bufs byte arrays to concatenate, from left to right
   * @return     The new constructed byte array with its value being the concatenation of
   *             {@param bufs}
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
   * Returns the last N bytes of data in an byte array
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
   *
   * <p>Internally, this invokes {@link #hex(byte[], String)}</p>
   *
   * @see #hex(byte[], String)
   */
  static String hex(byte[] buf) {
    return hex(buf, ":");
  }

  /**
   * Generates the hexadecimal encoded string for a byte array, each byte (2 characters) is
   * separated by a separator
   *
   * @param buf Input byte buffer
   * @param sep Separator for each byte
   * @return    The hexadecimal string represents the input bytes {@param buf}
   *
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
   * Generates the unique identifier of byte array for a bytes array
   *
   * @param data Input byte array
   * @param md   The one-way hash algorithm to use to generate the finger print
   * @return     The finger print byte array represents the input bytes {@param data}
   *
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
   * Generates thes hexadecimal encoded MD5 hash string for a byte array.
   *
   * <p>Internally, this invokes {@link #hex(byte[])} and {@link #fingerPrint(byte[], MessageDigest)}</p>
   *
   * @param data Input byte buffer
   * @return     The MD5 hash string represents the input bytes {@param data}
   *
   * @see <a href="https://en.wikipedia.org/wiki/MD5">MD5</a>
   * @see #hex(byte[])
   * @see #fingerPrint(byte[], MessageDigest)
   */
  public static String md5(final byte[] data) {
    if (data == null) {
      throw new IllegalArgumentException("Invalid key parameter - key is null");
    }

    return hex(fingerPrint(data, Objects.requireNonNull(DigestFactories.md5.create())));
  }

  /**
   * Generate the hexdecimal encoded SHA256 hash string for a given byte array
   *
   * <p>Internally, this invokes {@link #fingerPrint(byte[], MessageDigest)}</p>
   *
   * @param data Input byte buffer
   * @return     The SHA256 hash string represents the input bytes {@param data}
   *
   * @see <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>
   * @see #fingerPrint(byte[], MessageDigest)
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
