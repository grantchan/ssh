package io.github.grantchan.ssh.server.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.compression.Compression;
import io.github.grantchan.ssh.common.transport.handler.AbstractPacketEncoder;
import io.github.grantchan.ssh.server.ServerSession;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

public class PacketEncoder extends AbstractPacketEncoder {

  private final ServerSession session;

  public PacketEncoder(ServerSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  protected Session getSession() {
    return session;
  }

  @Override
  protected Cipher getCipher() {
    return session.getS2cCipher();
  }

  @Override
  protected int getCipherSize() {
    return session.getS2cCipherSize();
  }

  @Override
  protected Mac getMac() {
    return session.getS2cMac();
  }

  @Override
  protected int getMacSize() {
    return session.getS2cMacSize();
  }

  @Override
  protected int getDefMacSize() {
    return session.getS2cDefMacSize();
  }

  @Override
  protected Compression getCompression() {
    return session.getS2cCompression();
  }
}