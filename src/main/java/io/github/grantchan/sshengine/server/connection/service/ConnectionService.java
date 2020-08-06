package io.github.grantchan.sshengine.server.connection.service;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.Service;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.connection.Channel;
import io.github.grantchan.sshengine.common.connection.ChannelFactories;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.util.Objects;

public class ConnectionService extends AbstractLogger implements Service {

  private final ServerSession session;

  public ConnectionService(ServerSession session) {
    this.session = session;
  }

  @Override
  public void handle(int cmd, ByteBuf req) throws Exception {
    logger.debug("[{}] Handling message - {} ...", session, SshMessage.from(cmd));

    switch (cmd) {
      case SshMessage.SSH_MSG_CHANNEL_OPEN:
        channelOpen(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_WINDOW_ADJUST:
        channelWindowAdjust(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_DATA:
        channelData(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_EOF:
        channelEof(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_CLOSE:
        channelClose(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_REQUEST:
        channelRequest(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_SUCCESS:
        break;

      case SshMessage.SSH_MSG_CHANNEL_FAILURE:
        break;

      default:
//        throw new IllegalStateException("Unsupported request: " + SshMessage.from(cmd));
    }
  }

  private void channelOpen(ByteBuf req) {

    /*
     * 5.1.  Open a Channel
     *
     * When either side wishes to open a new channel, it allocates a local
     * number for the channel.  It then sends the following message to the
     * other side, and includes the local channel number and initial window
     * size in the message.
     *
     *    byte      SSH_MSG_CHANNEL_OPEN
     *    string    channel type in US-ASCII only
     *    uint32    sender channel
     *    uint32    initial window size
     *    uint32    maximum packet size
     *    ....      channel type specific data follows
     *
     * The 'channel type' is a name, as described in [SSH-ARCH] and
     * [SSH-NUMBERS], with similar extension mechanisms.  The 'sender
     * channel' is a local identifier for the channel used by the sender of
     * this message.  The 'initial window size' specifies how many bytes of
     * channel data can be sent to the sender of this message without
     * adjusting the window.  The 'maximum packet size' specifies the
     * maximum size of an individual data packet that can be sent to the
     * sender.  For example, one might want to use smaller packets for
     * interactive connections to get better interactive response on slow
     * links.
     *
     * The remote side then decides whether it can open the channel, and
     * responds with either SSH_MSG_CHANNEL_OPEN_CONFIRMATION or
     * SSH_MSG_CHANNEL_OPEN_FAILURE.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4254#section-5.1">Opening a Channel</a>
     */
    String type = ByteBufIo.readUtf8(req);
    int peerId = req.readInt();
    long rwndsize = req.readUnsignedInt();
    long rpksize = req.readUnsignedInt();

    logger.debug("[{}] Received SSH_MSG_CHANNEL_OPEN. channel type:{}, sender channel id:{}, " +
        "initial window size:{}, maximum packet size:{}", session, type, peerId, rwndsize, rpksize);

    Channel channel = Objects.requireNonNull(ChannelFactories.from(type)).create(session);
    channel.open(peerId, (int)rwndsize, (int)rpksize)
           .whenComplete((isOpened, ex) -> {
             if (isOpened != null && isOpened) {
               Window wnd = channel.getLocalWindow();

               session.replyChannelOpenConfirmation(peerId,
                                                    channel.getId(),
                                                    wnd.getMaxSize(),
                                                    wnd.getPacketSize());
             } else {
               // failed to open
               int reason = 0;
               String message = "Error while opening channel, id: " + peerId;
               if (ex != null) {
                 if (ex instanceof SshException) {
                   reason = ((SshException) ex).getReason();
                 }
                 message = ex.getMessage();
               }
               session.replyChannelOpenFailure(peerId, reason, message, "");
             }
           });
  }

  private void channelWindowAdjust(ByteBuf req) {
    int id = req.readInt();

    Channel channel = Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleWindowAdjust(req);
  }

  private void channelData(ByteBuf req) throws IOException {
    int id = req.readInt();

    Channel channel = Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleData(req);
  }

  private void channelEof(ByteBuf req) throws IOException {
    int id = req.readInt();

    Channel channel = Channel.get(id);
    if (channel == null) {
      logger.debug("[{}] Channel (id={}) not found, ignored", session, id);
      return;
    }

    channel.handleEof(req);
  }

  private void channelClose(ByteBuf req) throws IOException {
    int id = req.readInt();

    Channel channel = Channel.get(id);
    if (channel == null) {
      logger.debug("[{}] Channel (id={}) not found, ignored", session, id);
      return;
    }

    channel.handleClose(req);
  }

  private void channelRequest(ByteBuf req) throws IOException {
    int id = req.readInt();

    Channel channel = Channel.get(id);
    if (channel == null) {
      throw new IllegalStateException("Channel not found - id:" + id);
    }

    channel.handleRequest(req);
  }
}
