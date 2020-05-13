package io.github.grantchan.sshengine.util.iostream;

import io.github.grantchan.sshengine.util.buffer.Bytes;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public final class Reader {
  /**
   * @param in  the {@link InputStream} to read from
   * @return    {@link String} object read from {@link InputStream} {@code in}
   * @throws IOException  if error happens while reading
   */
  public static String readLengthUtf8(InputStream in) throws IOException {
    byte[] val = readLengthBytes(in);
    return new String(val, StandardCharsets.UTF_8);
  }

  /**
   * @param in  the {@link InputStream} to read from
   * @return    {@link BigInteger} object read from {@link InputStream} {@code in}
   * @throws IOException  if error happens while reading
   */
  public static BigInteger readMpInt(InputStream in) throws IOException {
    return new BigInteger(readLengthBytes(in));
  }

  /**
   * Read limited number of bytes from {@link InputStream}, the number of bytes to read is indicated
   * at the first integer buffer in {@code in}
   * @param in  the {@link InputStream} to read from
   * @return    byte buffer in {@code in}
   * @throws IOException  if any error happens while reading
   */
  private static byte[] readLengthBytes(InputStream in) throws IOException {
    int len = readInt(in);

    return readBytes(in, len);
  }

  /**
   * Read an integer from {@link InputStream}
   * @param in  the {@link InputStream} to read from
   * @return    the integer read from {@code in}
   * @throws IOException  if error happens while reading
   * @throws EOFException if not enough data to read
   */
  private static int readInt(InputStream in) throws IOException {
    byte[] bytes = readBytes(in, Integer.BYTES);
    if (bytes == null || Integer.BYTES != bytes.length) {
      throw new EOFException("Not enough data to read. expected: " + Integer.BYTES +
          ", actual: " + (bytes != null ? bytes.length : 0));
    }
    return (int) Bytes.readBigEndian(bytes);
  }

  /**
   * Read bytes from {@link InputStream} as much as possible until reaching required {@code length}
   * or EOF
   * @param in      the {@link InputStream} to read from
   * @param length  number of the byte data want to read from {@code in}
   * @return        bytes actually read from {@code in}
   * @throws IOException  if error happens while reading
   */
  private static byte[] readBytes(InputStream in, int length) throws IOException {
    byte[] data = new byte[length];
    int cnt = in.read(data);
    if (cnt == -1) {  // reach the end of stream, no data is read
      return null;
    }

    if (cnt < length) {
      byte[] dest = new byte[cnt];
      System.arraycopy(data, 0, dest, 0, cnt);
      data = dest;
    }
    return data;
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private Reader() {}
}
