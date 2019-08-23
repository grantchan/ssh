package io.github.grantchan.SshEngine.server.connection.service;

import io.github.grantchan.SshEngine.arch.SshMessage;
import io.github.grantchan.SshEngine.common.Service;
import io.github.grantchan.SshEngine.common.Session;
import io.github.grantchan.SshEngine.common.connection.Channel;
import io.github.grantchan.SshEngine.common.connection.ChannelFactories;
import io.github.grantchan.SshEngine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

public class ConnectionService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Session session;

  public ConnectionService(Session session) {
    this.session = session;
  }

  @Override
  public void handle(int cmd, ByteBuf req) {
    logger.info("[{}] Handling message - {} ...", session, SshMessage.from(cmd));

    switch (cmd) {
      case SshMessage.SSH_MSG_CHANNEL_OPEN:
        handleChannelOpen(req);
        break;

      case SshMessage.SSH_MSG_CHANNEL_DATA:
        break;

      case SshMessage.SSH_MSG_CHANNEL_CLOSE:
        break;

      case SshMessage.SSH_MSG_CHANNEL_REQUEST:
        break;

      case SshMessage.SSH_MSG_CHANNEL_SUCCESS:
        break;

      case SshMessage.SSH_MSG_CHANNEL_FAILURE:
        break;

      default:
//        throw new IllegalStateException("Unsupported request: " + SshMessage.from(cmd));
    }
  }

  private void handleChannelOpen(ByteBuf req) {

    /*
     * RFC 4254:
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
    int remoteId = req.readInt();
    long wndSize = req.readUnsignedInt();
    long maxPacketSize = req.readUnsignedInt();

    logger.debug("[{}] Received SSH_MSG_CHANNEL_OPEN. channel type={}, sender channel id={}, " +
        "initial window size={}, maximum packet size={}", session, type, remoteId, wndSize,
        maxPacketSize);

    Channel channel = Objects.requireNonNull(ChannelFactories.from(type), "Unknown channel type")
                             .create();

    session.replyChannelOpenConfirmation(remoteId, channel.getId(), 2097152, 32768);
  }
}
