package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;

import java.io.Closeable;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The class implements the sizing window with necessary synchronization.
 */
public class Window extends AbstractLogger implements Closeable {

  private static final int DEFAULT_SIZE = 0x200000;
  private static final int DEFAULT_PACKET_SIZE = 0x8000;

  /**
   * Name of this window assigned to indicate properties, eg. client, server, local, remote
   * it's formatted as: (client or server)/(local or remote). For example: client/local, server/local
   */
  private final String name;

  /** A lock that used to provide synchronization */
  private final Object lock = this;

  private Channel channel;

  /** Current size of this window */
  private int size;

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

  public Window(Channel channel, String name) {
    this(channel, name, DEFAULT_SIZE, DEFAULT_PACKET_SIZE);
  }

  public Window(Channel channel, String name, int maxSize, int packetSize) {
    this.channel = channel;

    this.name = name;

    this.size = maxSize;  // Initially, it's same as max size

    this.maxSize = maxSize;
    this.packetSize = packetSize;
  }

  public int getSize() {
    return size;
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
   * Wait a period of time for the window size to update to specific length of space
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

      while (isOpen.get() && (size < len)) {
        lock.wait(timeout);

        // consume or expand might cause the window size change, then notify all the waiting threads
        // the above wait could be waken as well
        duration -= System.currentTimeMillis() - waitStart;

        // After wake up, we need to check if the wait time is up, if yes, throw
        // WindowTimeoutException, if no, wait again
        if (duration <= 0 && size < len) {
          throw new WindowTimeoutException("Timeout after waiting " + timeout + "milliseconds - "
              + this);
        }
      }
    }

    if (!isOpen.get()) {
      throw new WindowClosedException("Window is closed - " + this);
    }
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
      if (size + len > maxSize) {
        throw new IllegalStateException("Too big to expand, the maximum window size is:" + maxSize +
            ", but len:" + len);
      }

      size += len;

      lock.notifyAll();

      logger.trace("{}, {} bytes expanded", this, len);
    }
  }

  /**
   * Consume the space in the window. It shrinks the window size, usually called when bytes are sent
   *
   * @param len  bytes consumed
   */
  public void consume(int len) {
    synchronized (lock) {
      if (len > size) {
        throw new IllegalStateException("Not enough space to consume, current size: " + size +
            ", but len: " + len);
      }

      size -= len;

      lock.notifyAll();

      logger.trace("{}, {} bytes consumed", this, len);
    }
  }

  @Override
  public void close() {
    if (isOpen.getAndSet(false)) {
      logger.debug("{} is closed", this);
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
