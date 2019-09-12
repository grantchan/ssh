package io.github.grantchan.SshEngine.common.connection;

import io.github.grantchan.SshEngine.common.AbstractLogger;

public class Window extends AbstractLogger {

  private static final int DEFAULT_SIZE = 0x200000;
  private static final int DEFAULT_PACKET_SIZE = 0x8000;

  private Channel channel;

  private int size;
  private int packetSize;

  public Window(Channel channel) {
    this(channel, DEFAULT_SIZE, DEFAULT_PACKET_SIZE);
  }

  public Window(Channel channel, int size, int packetSize) {
    this.channel = channel;
    this.size = size;
    this.packetSize = packetSize;
  }

  public int getSize() {
    return size;
  }

  public int getPacketSize() {
    return packetSize;
  }
}
