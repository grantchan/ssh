package io.github.grantchan.sshengine.server.connection;

import java.io.IOException;

public interface WritableStream {

  /**
   * Write an integer to the stream
   *
   * @param b  the integer to be written to the stream
   * @throws IOException  if error happens while writing
   */
  void write(int b) throws IOException;

  /**
   * Write a bunch of bytes to the stream
   *
   * @param buf  the byte array to be written to the stream
   * @throws IOException  if error happens while writing
   */
  default void write(byte[] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  /**
   * Write a bunch of bytes to the stream
   *
   * @param buf  the byte array to be written to the stream
   * @param off  the start position at the array to indicate the data start to write from
   * @param len  length of data in the array to write to the stream
   * @throws IOException  if error happens while writing
   */
  default void write(byte[] buf, int off, int len) throws IOException {
    for (int i = off; i < off + len; i++) {
      write(buf[i]);
    }
  }
}
