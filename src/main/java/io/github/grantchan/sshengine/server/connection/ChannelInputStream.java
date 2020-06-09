package io.github.grantchan.sshengine.server.connection;

import java.io.InputStream;
import java.util.Deque;
import java.util.LinkedList;

public class ChannelInputStream extends InputStream
                                implements WritableStream {

  private final Deque<Byte> fifo = new LinkedList<>();

  @Override
  public int available() {
    return fifo.size();
  }

  @Override
  public int read() {
    return fifo.size() > 0 ? fifo.poll() : -1;
  }

  @Override
  public int read(byte[] b, int off, int len) {
    int nb = 0;
    for (int i = off; i < off + len; i++, nb++) {
      b[i] = (byte) read();
    }

    return nb;
  }

  @Override
  public void write(int b) {
    fifo.add((byte) b);
  }
}
