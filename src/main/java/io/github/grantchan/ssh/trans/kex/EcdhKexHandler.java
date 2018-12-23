package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.security.MessageDigest;

public class EcdhKexHandler extends KexHandler {

  public EcdhKexHandler(MessageDigest md, Session session) {
    super(md, session);
  }

  @Override
  public void handleMessage(int cmd, ByteBuf req) throws IOException {
  }

}
