package io.github.grantchan.sshengine.client.connection.service;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.connection.AbstractClientChannel;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.Service;
import io.github.grantchan.sshengine.common.connection.Channel;
import io.github.grantchan.sshengine.common.transport.handler.SessionHolder;
import io.netty.buffer.ByteBuf;

import java.io.IOException;

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
      case SshMessage.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        channelOpenConfirmation(req);
        break;

      default:
        break;
    }
  }

  private void channelOpenConfirmation(ByteBuf req) throws IOException {
    int id = req.readInt();

    Channel channel = Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    ((AbstractClientChannel)channel).handleOpenConfirmation(req);
  }
}
