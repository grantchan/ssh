package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.compression.Compression;
import io.github.grantchan.ssh.common.transport.handler.AbstractPacketDecoder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

public class ClientPacketDecoder extends AbstractPacketDecoder {

  private ClientSession session;

  ClientPacketDecoder(ClientSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public Session getSession() {
    return this.session;
  }

  @Override
  public Cipher getCipher() {
    return session.getS2cCipher();
  }

  @Override
  public int getBlkSize() {
    return session.getS2cCipherSize();
  }

  @Override
  public Mac getMac() {
    return session.getS2cMac();
  }

  @Override
  public int getMacSize() {
    return session.getS2cMacSize();
  }

  @Override
  public Compression getCompression() {
    return session.getS2cCompression();
  }
}
