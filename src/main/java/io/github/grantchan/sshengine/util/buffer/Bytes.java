package io.github.grantchan.sshengine.util.buffer;

import io.github.grantchan.sshengine.common.transport.digest.DigestFactories;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Function;

public final class Bytes {

  /** An single byte immutable array, in which the value is zero */
  private static final byte[] ZERO = new byte[] {0};
  /** An single byte immutable array, in which the value is one */
  private static final byte[] ONE = new byte[] {1};

  static final Function<byte[], byte[]> SEPARATE_BY_LENGTH =
      e -> Bytes.toBytes(e.length);

  static final Function<byte[], byte[]> MP_SEPARATE_BY_LENGTH =
      e -> {
        if ((e[0] & 0x80) != 0) {
          return concat(toBytes(e.length + 1), ZERO);
        } else {
          return Bytes.toBytes(e.length);
        }
      };

  /**
   * Returns an single byte array, in which if the parameter {@code b} is true, the byte is 1,
   * otherwise, 0.
   */
  public static byte[] toArray(boolean b) {
    return b ? ONE : ZERO;
  }

  /**
   * Resizes an array.
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
    Objects.requireNonNull(array, "Invalid parameter - array is null");

    if (array.length > newSize) {
      byte[] tmp = new byte[newSize];
      System.arraycopy(array, 0, tmp, 0, newSize);

      return tmp;
    }
    return array;
  }

  /**
   * Convert an unsigned integer to big-endian (network byte order) byte array
   *
   * @param num The unsigned integer in host byte order
   * @return    The network byte order byte array of {@code num}
   *
   * @see <a href="https://en.wikipedia.org/wiki/Endianness">Endianness</a>
   */
  public static byte[] toBytes(long num) {
    return new byte[] {
        (byte) (num >>> 24),
        (byte) (num >>> 16),
        (byte) (num >>> 8),
        (byte) (num)
    };
  }

  /**
   * Reads a network byte order(big-endian) integer from a byte array.
   *
   * <p>Internally, this invokes {@link #readBigEndian(byte[], int, int)}</p>
   *
   * @param array The byte array, has the integer in network byte order, to be read from.
   *              <p>
   *                Note: When {@code buf} contains more than {@link Integer#BYTES} bytes, only the
   *                first {@link Integer#BYTES} will be used.
   *              </p>
   * @return      The unsigned {@code long} integer
   * @throws IllegalArgumentException if the given array contains less than {@link Integer#BYTES}
   *                                  bytes
   *
   * @see #readBigEndian(byte[], int, int)
   */
  public static long readBigEndian(byte[] array) {
    return readBigEndian(array, 0, array.length);
  }

  /**
   * Reads a network byte order(big-endian) integer from a byte array.
   *
   * @param array The byte array, has the integer in network byte order, to be read from
   *              <p>
   *                Note: When {@param array} contains more than {@link Integer#BYTES} bytes,
   *                only the first {@link Integer#BYTES} will be used.
   *              </p>
   * @param off   The offset in {@param array}
   * @param len   Length of data in {@param array} to use to read
   * @return      The unsigned {@code long} integer
   * @throws IllegalArgumentException if the given array contains less than {@link Integer#BYTES}
   *                                  bytes
   */
  public static long readBigEndian(byte[] array, int off, int len) {
    Objects.requireNonNull(array);

    if (len < Integer.BYTES) {
      throw new IllegalArgumentException("Not enough data to convert to an unsigned integer, " +
          "required: " + Integer.BYTES + ", actual: " + array.length);
    }

    long n = 0;
    for (int i = 0, sh = Integer.SIZE - Byte.SIZE; i < Integer.BYTES; i++, sh -= Byte.SIZE) {
      n |= (array[off + i] & 0xFFL) << sh;
    }

    return n;
  }

  public static byte[] join(Function<byte[], byte[]> separator, byte[]... arrays) {
    Objects.requireNonNull(arrays, "Invalid parameter - arrays is null");

    // sum up the total length
    int size = 0;
    for (byte[] array : arrays) {
      if (array != null) {
        size += array.length;
        if (separator != null) {
          size += separator.apply(array).length;
        }
      }
    }

    if (size == 0) {
      return null;
    }

    byte[] res = new byte[size];
    int off = 0;
    for (byte[] array : arrays) {
      if (array != null) {
        if (separator != null) {
          // write separator
          byte[] sep = separator.apply(array);
          System.arraycopy(sep, 0, res, off, sep.length);
          off += sep.length;
        }

        // write the actual buffer
        System.arraycopy(array, 0, res, off, array.length);
        off += array.length;
      }
    }

    return res;
  }

  /**
   * Combines a set of byte arrays into a new array.
   *
   * <p>
   *   For example,<br/>
   *   {@code concat(new byte[]{a}, null, new byte[]{b, c})} returns an array {@code {a, b, c}}
   * </p>
   *
   * @param arrays Byte arrays to concatenate, from left to right
   * @return       The new constructed byte array with its value being the concatenation of
   *               {@code arrays}
   */
  public static byte[] concat(byte[]... arrays) {
    return join(null, arrays);
  }

  public static byte[] joinWithLength(byte[]... arrays) {
    return join(SEPARATE_BY_LENGTH, arrays);
  }

  public static byte[] joinWithLength(String... utf8) {
    byte[][] arrays = new byte[utf8.length][];
    for (int i = 0; i < utf8.length; i++) {
      if (utf8[i] != null) {
        arrays[i] = utf8[i].getBytes(StandardCharsets.UTF_8);
      }
    }

    return join(SEPARATE_BY_LENGTH, arrays);
  }

  public static byte[] joinWithLength(BigInteger... nums) {
    byte[][] arrays = new byte[nums.length][];
    for (int i = 0; i < nums.length; i++) {
      if (nums[i] != null) {
        arrays[i] = nums[i].toByteArray();
      }
    }

    return join(MP_SEPARATE_BY_LENGTH, arrays);
  }

  public static byte[] addLen(byte[] buf) {
    return joinWithLength(buf);
  }

  public static byte[] addLen(String str) {
    return joinWithLength(str);
  }

  public static byte[] addLen(BigInteger num) {
    return joinWithLength(num);
  }

  /**
   * Returns the last N bytes of data in an byte array
   */
  public static byte[] last(byte[] buf, int len) {
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
   * @return    The hexadecimal string represents the input bytes {@code buf}
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
   * @return     The finger print byte array represents the input bytes {@code data}
   *
   * @see <a href="https://en.wikipedia.org/wiki/Fingerprint_(computing)">Fingerprint (computing)</a>
   */
  private static byte[] fingerPrint(byte[] data, MessageDigest md) {
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
   * @return     The MD5 hash string represents the input bytes {@code data}
   *
   * @see <a href="https://en.wikipedia.org/wiki/MD5">MD5</a>
   * @see #hex(byte[])
   * @see #fingerPrint(byte[], MessageDigest)
   */
  public static String md5(byte[] data) {
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
   * @return     The SHA256 hash string represents the input bytes {@code data}
   *
   * @see <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>
   * @see #fingerPrint(byte[], MessageDigest)
   */
  public static String sha256(byte[] data) {
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
