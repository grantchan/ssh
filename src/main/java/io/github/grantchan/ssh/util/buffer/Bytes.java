package io.github.grantchan.ssh.util.buffer;

import java.util.Arrays;
import java.util.Objects;

public final class Bytes {

  /**
   * Resize the {@code array} to a new size.
   * <p>If the {@code newSize} is smaller than the original {@code array} size, extra bytes will be
   * truncated.<br>
   * If the {@code newSize} is bigger than or equal to the {@code array} size, just return the
   * {@code array}</p>
   *
   * @param array the array to be resized
   * @param newSize new size of the array to be resized to
   * @return a new resized array or the original array.
   */
  public static byte[] resize(byte[] array, int newSize) {
    if (Objects.requireNonNull(array).length > newSize) {
      byte[] tmp = new byte[newSize];
      System.arraycopy(array, 0, tmp, 0, newSize);
      array = tmp;
    }
    return array;
  }

  /**
   * Convert the unsigned integer {@code i} from little-endian(host byte order) to big-endian
   * (network byte order) byte array
   *
   * @param i the unsigned integer in host byte order
   * @return the network byte order byte array of {@code i}
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
   * @param buf  the buffer has the integer in network byte order.
   *             <p><b>Note:</b> When {@code buf} contains more than {@code Integer.BYTES} bytes,
   *             only the first {@code Integer.BYTES} will be used.</p>
   * @return the unsigned {@code long} integer
   * @throws IllegalArgumentException if {@code buf} contains less than {@code Integer.BYTES} bytes
   */
  public static long nl(byte[] buf) {
    return nl(buf, 0, buf.length);
  }

  /**
   * Read a network byte order(big-endian) integer from buffer {@code buf}
   * @param buf  the buffer has the integer in network byte order.
   *             <p><b>Note:</b> When {@code buf} contains more than {@code Integer.BYTES} bytes,
   *             only the first {@code Integer.BYTES} will be used.</p>
   * @param off  The offset in {@code buf}
   * @param len  Length of data in {@code buf} to use to read
   * @return the unsigned {@code long} integer
   * @throws IllegalArgumentException if {@code buf} contains less than {@code Integer.BYTES} bytes
   */
  public static long nl(byte[] buf, int off, int len) {
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
   * @param bufs byte arrays to concatenate, from left to right
   * @return the newly constructed byte array with its value being the concatenation of {@code bufs}
   */
  public static byte[] concat(byte[]... bufs) {
    if (bufs == null) {
      return null;
    }

    // sum up the total length
    int len = 0;
    for (byte[] buf : bufs) {
      if (buf != null) {
        len += buf.length;
      }
    }

    if (len == 0) {
      return null;
    }

    byte[] result = new byte[len];
    int cnt = 0;
    for (byte[] buf : bufs) {
      if (buf != null) {
        System.arraycopy(buf, 0, result, cnt, buf.length);
        cnt += buf.length;
      }
    }

    return result;
  }

  /**
   * Returns the last N bytes of data in {@code buf}
   */
  public static byte[] last(byte[] buf, int len) {
    if (Objects.requireNonNull(buf).length <= len) {
      return buf;
    }

    return Arrays.copyOfRange(buf, buf.length - len, buf.length);
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private Bytes() {}
}
