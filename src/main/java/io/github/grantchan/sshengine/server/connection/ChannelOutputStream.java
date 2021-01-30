package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class ChannelOutputStream extends OutputStream {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final static long DEFAULT_WAIT_SPACE_TIMEOUT = TimeUnit.SECONDS.toMillis(30);

  private final byte[] aByte = new byte[1];

  private byte[] buf;
  private int bufOff, bufLen;

  private final Channel channel;
  private final boolean extended;
  private final long waitTimeout;

  public ChannelOutputStream(Channel channel, boolean extended) {
    this(channel, extended, DEFAULT_WAIT_SPACE_TIMEOUT);
  }

  public ChannelOutputStream(Channel channel, boolean extended, long waitTimeout) {
    this.channel = Objects.requireNonNull(channel, "Invalid parameter - channel is null");
    this.extended = extended;
    this.waitTimeout = waitTimeout;
  }

  @Override
  public synchronized void write(int b) throws IOException {
    aByte[0] = (byte) b;
    write(aByte, 0, 1);
  }

  @Override
  public synchronized void write(byte[] b, int off, int len) throws IOException {
    AbstractSession session = channel.getSession();

    if (!channel.isOpen()) {
      logger.debug("[{}] Failed to write data to a closed channel ({})", session, channel);

      throw new SshChannelException("Unable to write data via channel: " + channel.getId() +
          ", channel is closed.");
    }

    Window rWnd = channel.getRemoteWindow();

    while (len > 0) {
      int avail = Math.min(len, Math.min(rWnd.getSize(), rWnd.getPacketSize()));
      while (avail <= 0) {
        try {
          rWnd.waitForSpace(1, waitTimeout);

          avail = Math.min(len, Math.min(rWnd.getSize(), rWnd.getPacketSize()));

          logger.debug("[{} - {}] Window size is updated, {} bytes available", session, channel,
              rWnd.getSize());
        } catch (WindowClosedException ce) {
          logger.debug("[{} - {}] Window is closed, not enough space - {} bytes to send data",
              session, channel, avail);

          throw ce;
        } catch (WindowTimeoutException te) {
          logger.debug("[{} - {}] Timeout after {} seconds wait", session, channel,
              TimeUnit.MILLISECONDS.toSeconds(waitTimeout));

          throw te;
        } catch (InterruptedException e) {
          throw new InterruptedIOException(e.getMessage());
        }
      }

      buf = b;
      bufOff = off;
      bufLen = avail;

      rWnd.consume(bufLen);

      flush();

      off += avail;
      len -= avail;
    }
  }

  @Override
  public synchronized void flush() throws IOException {
    if (buf == null || bufLen == 0) {
      return;
    }

    AbstractSession session = channel.getSession();

    if (!channel.isOpen()) {
      logger.debug("[{}] Failed to write data to a closed channel ({})", session, channel);

      throw new SshChannelException("Unable to write data via channel: " + channel.getId() +
          ", channel is closed");
    }

    if (extended) {
      session.replyChannelExtendedData(channel.getPeerId(), buf, bufOff, bufLen);
    } else {
      session.replyChannelData(channel.getPeerId(), buf, bufOff, bufLen);
    }

    buf = null;
    bufLen = 0;
  }

  @Override
  public synchronized void close() throws IOException {
    if (channel.isOpen()) {
      try {
        logger.debug("[{}] Flush data before channel({}) is closed", channel.getSession(), channel);

        flush();
      } finally {
        channel.close();
      }
    }
  }
}
