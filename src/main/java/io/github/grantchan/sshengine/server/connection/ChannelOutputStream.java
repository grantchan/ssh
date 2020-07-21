package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.AbstractChannel;
import io.github.grantchan.sshengine.common.connection.SshChannelException;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

public class ChannelOutputStream extends OutputStream {

  private final byte[] aByte = new byte[1];

  private byte[] buf;
  private int bufOff, bufLen;

  private final AbstractChannel channel;
  private final boolean extended;

  public ChannelOutputStream(AbstractChannel channel, boolean extended) {
    this.channel = Objects.requireNonNull(channel, "Invalid parameter - channel is null");
    this.extended = extended;
  }

  @Override
  public void write(int b) throws IOException {
    aByte[0] = (byte) b;
    write(aByte, 0, 1);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    if (!channel.isOpen()) {
      throw new SshChannelException("Unable to write data via channel: " + channel.getId() +
          ", channel is closed.");
    }

    buf = b;
    bufOff = off;
    bufLen = len;
  }

  @Override
  public void flush() {
    AbstractSession session = channel.getSession();

    if (extended) {
      session.replyChannelExtendedData(channel.getPeerId(), buf, bufOff, bufLen);
    } else {
      session.replyChannelData(channel.getPeerId(), buf, bufOff, bufLen);
    }
  }

  @Override
  public void close() {
    if (channel.isOpen()) {
      try {
        flush();
      } finally {
        channel.close();
      }
    }
  }
}
