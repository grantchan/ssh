package io.github.grantchan.sshengine.server.connection;

import java.io.IOException;

public interface WritableStream {

  void write(int b) throws IOException;

  default void write(byte[] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  default void write(byte[] buf, int off, int len) throws IOException {
    for (int i = off; i < off + len; i++) {
      write(buf[i]);
    }
  }
}
