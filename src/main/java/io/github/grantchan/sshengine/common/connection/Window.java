package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;

import java.io.Closeable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The class implements the sizing window with necessary synchronization.
 */
public class Window extends AbstractLogger implements Closeable {

  private static final int DEFAULT_MAX_SIZE = 0x200000;
  private static final int DEFAULT_PACKET_SIZE = 0x8000;

  /**
   * Name of this window assigned to indicate properties, eg. client, server, local, remote
   * it's formatted as: (client or server)/(local or remote).
   * <p>
   * For example: client/local, server/local
   * </p>
   */
  private final String name;

  /** A lock that used to provide synchronization */
  private final Object lock = this;

  private final AbstractChannel channel;

  /** Current size of this window */
  private final AtomicInteger size;

  /**
   * Total size of this window, it specifies how many bytes of channel data can be sent without
   * adjusting the window
   */
  private final int maxSize;

  /**
   * Maximum packet size, it specifies the maxmum size of an individual data packet that can be sent.
   * For example, one might want to use smaller packets for interactive connections to get better
   * interactive response on slow links.
   */
  private final int packetSize;

  /** Open status of this window, it's initiated as true */
  private AtomicBoolean isOpen  = new AtomicBoolean(true);

  public Window(AbstractChannel channel, String name) {
    this(channel, name, DEFAULT_MAX_SIZE, DEFAULT_PACKET_SIZE);
  }

  public Window(AbstractChannel channel, String name, int maxSize, int packetSize) {
    this.channel = channel;

    this.name = name;

    this.size = new AtomicInteger(maxSize);  // Initially, it's same as max size

    this.maxSize = maxSize;
    this.packetSize = packetSize;
  }

  public int getSize() {
    return size.get();
  }

  public int getMaxSize() {
    return maxSize;
  }

  public int getPacketSize() {
    return packetSize;
  }

  /**
   * @return true if this window is open, otherwise, false
   */
  public boolean isOpen() {
    return isOpen.get();
  }

  /**
   * Wait a period of time until the window size is updated to specific length of space
   *
   * @param len       window length to wait for
   * @param timeout   the maximum time to wait in milliseconds
   * @throws InterruptedException     if interrupted while waiting
   * @throws WindowClosedException    if window is closed while waiting
   * @throws WindowTimeoutException   if the timeout expired before space is updated
   */
  public void waitForSpace(int len, long timeout)
      throws InterruptedException, WindowClosedException, WindowTimeoutException {

    long duration = timeout;
    synchronized (lock) {
      long waitStart = System.currentTimeMillis();

      while (isOpen.get() && (size.get() < len)) {
        lock.wait(timeout);

        // consume or expand might cause the window size change, then notify all the waiting threads
        // the above wait could be waken as well
        duration -= System.currentTimeMillis() - waitStart;

        // After wake up, we need to check if the wait time is up, if yes, throw
        // WindowTimeoutException, if no, wait again
        if (duration <= 0 && size.get() < len) {
          throw new WindowTimeoutException("Timeout after waiting " + timeout + "milliseconds - "
              + this);
        }
      }
    }

    if (!isOpen.get()) {
      throw new WindowClosedException("Window is closed - " + this);
    }
  }

  private void setSize(int newSize) {
    int oldSize = size.getAndSet(newSize);

    logger.debug("[{}] {}, size updated: {} => {}", channel.getSession(), this, oldSize, size.get());
  }

  /**
   * Expand the window size
   *
   * @param len  bytes to expand
   */
  public void expand(int len) {
    if (len < 0) {
      throw new IllegalArgumentException("Invalid argument - len is negative");
    }

    synchronized (lock) {
      logger.debug("[{}] {}, trying to expand {} bytes", channel.getSession(), this, len);

      if (size.get() + len > maxSize) {
        throw new IllegalStateException("Too big to expand, the maximum window size is:" + maxSize +
            ", but len:" + len);
      }

      setSize(size.get() + len);

      lock.notifyAll();
    }
  }

  /**
   * Consume the space in the window. It shrinks the window size, usually called when bytes are sent
   *
   * @param len  bytes consumed
   */
  public void consume(int len) {
    synchronized (lock) {
      logger.debug("[{}] {}, trying to consume {} bytes", channel.getSession(), this, len);

      if (size.get() < len) {
        throw new IllegalStateException("Not enough space to consume, current size: " + size +
            ", but len: " + len);
      }

      setSize(size.get() - len);

      lock.notifyAll();
    }
  }

  public void ensureSpace() {
    synchronized (lock) {
      if (size.get() < maxSize / 2) {
        AbstractSession session = channel.getSession();

        session.sendWindowAdjust(channel.getPeerId(), maxSize - size.get());

        setSize(maxSize);
      }
    }
  }

  @Override
  public void close() {
    if (isOpen.getAndSet(false)) {
      logger.debug("[{}] {} is closed", channel.getSession(), this);
    }

    synchronized (lock) {
      lock.notifyAll();
    }
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + '(' + name + ") {channel=" + channel + ", size=" + size +
        ", open=" + isOpen.get() + '}';
  }
}
