package io.github.grantchan.sshengine.server.transport.handler;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.common.transport.handler.AbstractPacketDecoder;
import io.github.grantchan.sshengine.server.ServerSession;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

public class ServerPacketDecoder extends AbstractPacketDecoder {

  private final ServerSession session;

  public ServerPacketDecoder(ServerSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public Cipher getCipher() {
    return session.getC2sCipher();
  }

  @Override
  public int getBlkSize() {
    return session.getC2sCipherSize();
  }

  @Override
  public Mac getMac() {
    return session.getC2sMac();
  }

  @Override
  public int getMacSize() {
    return session.getC2sMacSize();
  }

  @Override
  public Compression getCompression() {
    return session.getC2sCompression();
  }
}
