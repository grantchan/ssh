package io.github.grantchan.sshengine.client.transport.handler;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.common.transport.handler.AbstractPacketEncoder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

public class ClientPacketEncoder extends AbstractPacketEncoder {

  private final ClientSession session;

  public ClientPacketEncoder(ClientSession session) {
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
  public int getCipherSize() {
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
  public int getDefMacSize() {
    return session.getC2sDefMacSize();
  }

  @Override
  public Compression getCompression() {
    return session.getC2sCompression();
  }
}