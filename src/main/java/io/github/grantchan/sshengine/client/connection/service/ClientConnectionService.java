package io.github.grantchan.sshengine.client.connection.service;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.Service;
import io.github.grantchan.sshengine.common.transport.handler.SessionHolder;
import io.netty.buffer.ByteBuf;

public class ClientConnectionService extends AbstractLogger implements Service, SessionHolder {

  private final ClientSession session;

  public ClientConnectionService(ClientSession session) {
    this.session = session;
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public void handle(int cmd, ByteBuf req) throws Exception {
    logger.debug("[{}] Handling message - {} ...", session, SshMessage.from(cmd));

    switch (cmd) {

      default:
        break;
    }
  }
}
