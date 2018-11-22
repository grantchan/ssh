package io.github.grantchan.ssh.util.buffer;

import java.util.Objects;

public final class ByteUtil {

  /**
   * Resize the {@code array} to a new size.
   * <p>If the {@code newSize} is smaller than the original {@code array} size, extra bytes will be
   * truncated.<br>
   * If the {@code newSize} is bigger than or equal to the {@code array} size, just return the
   * {@code array}</p>
   *
   * @param   array the array to be resized
   * @param   newSize new size of the array to be resized to
   * @return  a new resized array or the original array.
   */
  public static byte[] resizeKey(byte[] array, int newSize) {
    if (array.length > newSize) {
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
   * @param   i the unsigned integer in host byte order
   * @return  the network byte order byte array of {@code i}
   * @see     <a href="https://en.wikipedia.org/wiki/Endianness">Endianness</a>
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
   * Read a network byte order(big-endian) integer buffer
   * @param val  byte buffer represent the integer in network byte order
   * @return     unsigned integer represents {@code val}
   */
  public static int nl(byte[] val) {
    if (Objects.requireNonNull(val).length != Integer.BYTES) {
      throw new IllegalArgumentException("");
    }

    int n = 0;
    for (int i = 0, sh = Integer.SIZE - Byte.SIZE; i < val.length; i++, sh -= Byte.SIZE) {
      n |= (val[i] & 0xFF) << sh;
    }

    return n;
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private ByteUtil() {}
}
