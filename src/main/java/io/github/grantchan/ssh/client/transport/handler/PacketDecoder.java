package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.compression.Compression;
import io.github.grantchan.ssh.common.transport.handler.AbstractPacketDecoder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

public class PacketDecoder extends AbstractPacketDecoder {

  private ClientSession session;

  PacketDecoder(ClientSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  protected Session getSession() {
    return this.session;
  }

  @Override
  protected Cipher getCipher() {
    return session.getS2cCipher();
  }

  @Override
  protected int getBlkSize() {
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
  protected Compression getCompression() {
    return session.getS2cCompression();
  }
}
