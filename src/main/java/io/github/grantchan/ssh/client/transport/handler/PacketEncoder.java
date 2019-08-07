package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.transport.handler.AbstractPacketEncoder;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public class PacketEncoder extends AbstractPacketEncoder {

  public PacketEncoder(ClientSession session) {
    super(session);
  }

  @Override
  protected Cipher getCipher() {
    return session.getC2sCipher();
  }

  @Override
  protected int getCipherSize() {
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
  protected int getDefMacSize() {
    return session.getC2sDefMacSize();
  }
}