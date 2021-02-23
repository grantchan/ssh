package io.github.grantchan.sshengine.client.connection.service;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.connection.ClientChannel;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.Service;
import io.github.grantchan.sshengine.common.connection.Channel;
import io.github.grantchan.sshengine.common.transport.handler.SessionHolder;
import io.netty.buffer.ByteBuf;

public class ClientConnectionService extends AbstractLogger
                                     implements Service, SessionHolder {

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
    logger.debug("{} Handling message - {} ...", session, SshMessage.from(cmd));

    int id = req.readInt();

    ClientChannel channel = (ClientChannel) Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    switch (cmd) {
      case SshMessage.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        channel.handleOpenConfirmation(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_OPEN_FAILURE:
        channel.handleOpenFailure(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_DATA:
        channel.handleData(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_EXTENDED_DATA:
        channel.handleExtendedData(req);
        break;

      default:
        break;
    }
  }
}
