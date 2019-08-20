package io.github.grantchan.ssh.server.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.compression.Compression;
import io.github.grantchan.ssh.common.transport.handler.AbstractPacketDecoder;
import io.github.grantchan.ssh.server.ServerSession;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

public class PacketDecoder extends AbstractPacketDecoder {

  private final ServerSession session;

  public PacketDecoder(ServerSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public Session getSession() {
    return session;
  }

  @Override
  protected Cipher getCipher() {
    return session.getC2sCipher();
  }

  @Override
  protected int getBlkSize() {
    return session.getC2sCipherSize();
  }

  @Override
  protected Mac getMac() {
    return session.getC2sMac();
  }

  @Override
  protected int getMacSize() {
    return session.getC2sMacSize();
  }

  @Override
  protected Compression getCompression() {
    return session.getC2sCompression();
  }
}
