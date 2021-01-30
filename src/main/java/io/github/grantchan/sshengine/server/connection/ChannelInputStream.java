package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.connection.Channel;
import io.github.grantchan.sshengine.common.connection.Window;

import java.io.IOException;
import java.io.InputStream;
import java.util.Deque;
import java.util.LinkedList;

public class ChannelInputStream extends InputStream implements WritableStream {

  private final byte[] aByte = new byte[1];

  private final Channel channel;

  private final Deque<Byte> fifo = new LinkedList<>();

  public ChannelInputStream(Channel channel) {
    this.channel = channel;
  }

  @Override
  public int available() {
    return fifo.size();
  }

  @Override
  public synchronized int read() throws IOException {
    int n = read(aByte, 0, 1);
    if (n == -1) {
      return n;
    }

    return aByte[0];
  }

  @Override
  public synchronized int read(byte[] b, int off, int len) throws IOException {
    Window lWnd = channel.getLocalWindow();

    int nb = 0;
    for (int i = off; i < off + len; i++, nb++) {
      int val = fifo.size() > 0 ? fifo.poll() : -1;
      if (val == -1) {
        break;
      }

      b[i] = (byte) val;
    }

    lWnd.consume(nb);
    lWnd.ensureSpace();

    return nb;
  }

  @Override
  public synchronized void write(int b) {
    fifo.add((byte) b);
  }
}
