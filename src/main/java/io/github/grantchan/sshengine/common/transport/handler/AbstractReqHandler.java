package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.connection.Channel;
import io.github.grantchan.sshengine.common.transport.kex.KexGroup;
import io.github.grantchan.sshengine.common.transport.kex.KexGroupFactories;
import io.github.grantchan.sshengine.common.transport.kex.KexProposal;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

public abstract class AbstractReqHandler extends ChannelInboundHandlerAdapter
                                         implements ReqHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected AbstractSession session;

  private KexGroup kexGroup;

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public KexGroup getKexGroup() {
    return kexGroup;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf req = (ByteBuf) msg;
    int cmd = req.readByte() & 0xFF;

    handle(cmd, req);
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    logger.debug("[{}] Disconnecting... reason: {}, msg: {}",
        this, SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_CONNECTION_LOST),
        "Disconnected by peer");

    session.close(true)
           .whenComplete((closed, ex) -> {
             if (closed) {
               for (Channel c : Channel.find(session)) {
                 c.close();
               }
             }
           });
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
    AbstractSession session = Objects.requireNonNull(getSession(), "Session is not initialized");

    logger.debug("[" + session + "] exceptionCaught details", t);

    if (t instanceof SshException) {
      int reasonCode = ((SshException) t).getReason();
      if (reasonCode > 0) {
        session.notifyDisconnect(reasonCode, t.getMessage());
      }
    }
    ctx.channel().close();
  }

  public void handleDisconnect(ByteBuf req) throws Exception {
    AbstractSession session = Objects.requireNonNull(getSession(), "Session is not initialized");

    /*
     * RFC 4253:
     * The client sends SSH_MSG_DISCONNECT:
     *   byte      SSH_MSG_DISCONNECT
     *   uint32    reason code
     *   string    description in ISO-10646 UTF-8 encoding [RFC3629]
     *   string    language tag [RFC3066]
     *
     * This message causes immediate termination of the connection.  All
     * implementations MUST be able to process this message; they SHOULD be
     * able to send this message.
     *
     * The sender MUST NOT send or receive any data after this message, and
     * the recipient MUST NOT accept any data after receiving this message.
     * The Disconnection Message 'description' string gives a more specific
     * explanation in a human-readable form.  The Disconnection Message
     * 'reason code' gives the reason in a more machine-readable format
     * (suitable for localization)
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-11.1">Disconnection Message</a>
     */
    int code = req.readInt();
    String msg = ByteBufIo.readUtf8(req);

    logger.debug("[{}] Disconnecting... reason: {}, msg: {}", this,
        SshMessage.disconnectReason(code), msg);

    session.close(true)
           .whenComplete((closed, ex) -> {
             if (closed) {
               for (Channel c : Channel.find(session)) {
                 c.close();
               }
             }
           });
  }

  protected abstract void setKexInit(byte[] ki);

  @Override
  public void handleKexInit(ByteBuf msg) throws Exception {
    AbstractSession session = Objects.requireNonNull(getSession(), "Session is not initialized");

    /*
     * RFC 4253:
     * The client sends SSH_MSG_KEXINIT:
     *   byte         SSH_MSG_KEXINIT
     *   byte[16]     cookie (random bytes)
     *   name-list    kex_algorithms
     *   name-list    server_host_key_algorithms
     *   name-list    encryption_algorithms_client_to_server
     *   name-list    encryption_algorithms_server_to_client
     *   name-list    mac_algorithms_client_to_server
     *   name-list    mac_algorithms_server_to_client
     *   name-list    compression_algorithms_client_to_server
     *   name-list    compression_algorithms_server_to_client
     *   name-list    languages_client_to_server
     *   name-list    languages_server_to_client
     *   boolean      first_kex_packet_follows
     *   uint32       0 (reserved for future extension)
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-7.1">Algorithm Negotiation</a>
     */
    int startPos = msg.readerIndex();
    msg.skipBytes(SshConstant.MSG_KEX_COOKIE_SIZE);

    List<String> kexInit = resolveKexInit(msg);
    session.setKexInit(kexInit);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    byte[] kiBytes = new byte[payloadLen + 1];
    kiBytes[0] = SshMessage.SSH_MSG_KEXINIT;
    msg.getBytes(startPos, kiBytes, 1, payloadLen);

    kexGroup = KexGroupFactories.create(kexInit.get(KexProposal.Param.KEX), session);
    if (kexGroup == null) {
      throw new IOException("Unknown key exchange: " + KexProposal.Param.KEX);
    }

    setKexInit(kiBytes);
  }

  protected abstract List<String> resolveKexInit(ByteBuf buf);

  public void handleServiceRequest(ByteBuf req) throws SshException {
  }

  public void handleServiceAccept(ByteBuf req) throws SshException {
  }

  public void handleNewKeys(ByteBuf req) throws SshException {
  }
}
