package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.handler.IdExHandler;
import io.github.grantchan.ssh.common.transport.handler.PacketDecoder;
import io.github.grantchan.ssh.common.transport.handler.PacketEncoder;
import io.github.grantchan.ssh.common.transport.handler.RequestHandler;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class ClientRequestHandler extends RequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private ByteBuf accuBuf;
  private String username;

  public ClientRequestHandler(String username) {
    this.username = username;
  }

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    session = new ClientSession(ctx);

    /*
     * RFC 4253:
     * When the connection has been established, both sides MUST send an
     * identification string.  This identification string MUST be
     *
     *   SSH-protoversion-softwareversion SP comments CR LF
     *
     * Since the protocol being defined in this set of documents is version
     * 2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
     * OPTIONAL.  If the 'comments' string is included, a 'space' character
     * (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
     * and 'comments' strings.  The identification MUST be terminated by a
     * single Carriage Return (CR) and a single Line Feed (LF) character
     * (ASCII 13 and 10, respectively).
     *
     * ...
     *
     * The part of the identification string preceding the Carriage Return
     * and Line Feed is used in the Diffie-Hellman key exchange.
     *
     * ...
     *
     * Key exchange will begin immediately after sending this identifier.
     */
    session.setClientId("SSH-2.0-Client DEMO");
    session.setUsername(username);

    accuBuf = session.createBuffer();
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    String id = session.getServerId();
    if (id != null) {
      super.channelRead(ctx, msg);
      return;
    }

    accuBuf.writeBytes((ByteBuf) msg);

    id = IdExHandler.getId(accuBuf);
    if (id == null) {
      return;
    }
    session.setServerId(id);

    logger.debug("[{}] Received identification: {}", session, id);

    ctx.pipeline().addFirst(new PacketDecoder(session));
    ctx.pipeline().addLast(new PacketEncoder(session));

    ByteBuf ki = IdExHandler.kexInit();
    byte[] buf = new byte[ki.readableBytes()];
    ki.getBytes(SSH_PACKET_HEADER_LENGTH, buf);
    session.setC2sKex(buf);

    ki.readerIndex(0);

    ByteBuf composite = session.createBuffer();
    composite.writeBytes((session.getClientId() + "\r\n").getBytes(StandardCharsets.UTF_8));
    int idx = composite.writerIndex();
    composite.writeBytes(ki);
    composite.readerIndex(idx + SSH_PACKET_HEADER_LENGTH);

    ctx.channel().writeAndFlush(composite);

    ReferenceCountUtil.release(msg);
  }

  protected void handleServiceAccept(ByteBuf req) throws SshException {
    String service = ByteBufIo.readUtf8(req);

    logger.debug("[{}] Service accepted: {}", session, service);

    session.acceptService(service);

    /*
     * The "none" Authentication Request
     *
     * A client may request a list of authentication 'method name' values
     * that may continue by using the "none" authentication 'method name'.
     *
     * If no authentication is needed for the user, the server MUST return
     * SSH_MSG_USERAUTH_SUCCESS.  Otherwise, the server MUST return
     * SSH_MSG_USERAUTH_FAILURE and MAY return with it a list of methods
     * that may continue in its 'authentications that can continue' value.
     *
     * This 'method name' MUST NOT be listed as supported by the server.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.2">The "none" Authentication Request</a>
     */
    session.requestUserAuthRequest(session.getUsername(), "ssh-connection", "none");
  }

  protected void handleNewKeys(ByteBuf req) throws SshException {
    super.handleNewKeys(req);

    session.requestServiceRequest();
  }
}
