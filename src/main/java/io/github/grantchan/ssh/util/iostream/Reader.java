package io.github.grantchan.ssh.util.iostream;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static io.github.grantchan.ssh.util.buffer.ByteUtil.nl;

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
   * @throws IOException
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
  static byte[] readLengthBytes(InputStream in) throws IOException {
    int len = readInt(in);
    byte[] data = new byte[len];

    read(in, data);

    return data;
  }

  /**
   * Read an integer from {@link InputStream}
   * @param in  the {@link InputStream} to read from
   * @return    the integer read from {@code in}
   * @throws IOException  if error happens while reading
   * @throws EOFException if not enough data to read
   */
  static int readInt(InputStream in) throws IOException {
    byte[] bytes = new byte[Integer.BYTES];
    int bytesRead = read(in, bytes);
    if (Integer.BYTES != bytesRead) {
      throw new EOFException("Not enough data to read. expected: " + Integer.BYTES +
          ", actual: " + bytesRead);
    }
    return nl(bytes);
  }

  /**
   * Read bytes from {@link InputStream} as much as possible
   * @param in    the {@link InputStream} to read from
   * @param data  the byte data read from {@code in}
   * @return      number of bytes actually read from {@code in}
   * @throws IOException  if error happens while reading
   */
  static int read(InputStream in, byte[] data) throws IOException {
    return read(in, data, 0, data.length);
  }

  /**
   * Read bytes from {@link InputStream} as much as possible
   * @param in    the {@link InputStream} to read from
   * @param data  the byte data read from {@code in}
   * @param off   offset of {@code data} where data writes into
   * @param len   length to read
   * @return      number of bytes actually read from {@code in}
   * @throws IOException  if error happens while reading
   */
  static int read(InputStream in, byte[] data, int off, int len) throws IOException {
    int remain = len;
    while (remain > 0) {
      int cnt = in.read(data, off, len);
      if (cnt == -1) {
        return off - cnt;
      }
      remain -= cnt;
    }
    return len;
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private Reader() {}
}
