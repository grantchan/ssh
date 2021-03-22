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

import java.io.IOException;

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

    switch (cmd) {
      case SshMessage.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        channelOpenConfirmation(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_OPEN_FAILURE:
        channelOpenFailure(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_WINDOW_ADJUST:
        channelWindowAdjust(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_DATA:
        channelData(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_EXTENDED_DATA:
        channelExtendedData(req);
        break;

      default:
        break;
    }
  }

  private void channelOpenConfirmation(ByteBuf req) throws IOException {
    int id = req.readInt();

    ClientChannel channel = (ClientChannel) Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleOpenConfirmation(req);
  }

  private void channelOpenFailure(ByteBuf req) {
    int id = req.readInt();

    ClientChannel channel = (ClientChannel) Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleOpenFailure(req);
  }

  private void channelWindowAdjust(ByteBuf req) {
    int id = req.readInt();

    ClientChannel channel = (ClientChannel) Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleWindowAdjust(req);
  }

  private void channelData(ByteBuf req) throws IOException {
    int id = req.readInt();

    ClientChannel channel = (ClientChannel) Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleData(req);
  }

  private void channelExtendedData(ByteBuf req) throws IOException {
    int id = req.readInt();

    ClientChannel channel = (ClientChannel) Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleExtendedData(req);
  }


}
