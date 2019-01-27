package io.github.grantchan.ssh.client.transport.kex;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.github.grantchan.ssh.server.transport.kex.KexHandler;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;

public class CDhGroupHandler extends KexHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public CDhGroupHandler(MessageDigest md, KeyExchange kex, Session session) {
    super(md, kex, session);
  }

  @Override
  public void handleMessage(int cmd, ByteBuf msg) {
    logger.debug("Handling key exchange message - {} ...", SshMessage.from(cmd));

    if (cmd == SshMessage.SSH_MSG_KEXDH_INIT) {
      handleDhInit(msg);
    }
  }

  private void handleDhInit(ByteBuf msg) {
    byte[] e = kex.getPubKey();
    if (e == null) {
      throw new IllegalStateException("Key exchange is not initialized");
    }

    session.requestKexDhInit(e);
  }
}
