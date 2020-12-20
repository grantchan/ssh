package io.github.grantchan.sshengine.server.transport.handler;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.handler.IdExHandler;
import io.github.grantchan.sshengine.common.transport.handler.PacketDecoder;
import io.github.grantchan.sshengine.common.transport.handler.PacketEncoder;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public class ServerIdEx extends ChannelInboundHandlerAdapter implements IdExHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected ServerSession session;

  private ByteBuf accrued;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    session = new ServerSession(ctx.channel());
    accrued = session.createBuffer();
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) {
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
    String id = "SSH-2.0-Server DEMO";
    session.setServerId(id);

    ctx.writeAndFlush(Unpooled.wrappedBuffer((id + "\r\n").getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    accrued.writeBytes((ByteBuf) msg);

    String id = session.getClientId();
    if (id == null) {
      id = IdExHandler.getId(accrued);
      if (id == null) {
        return;
      }

      logger.debug("[{}] Received identification: {}", session, id);
      session.setClientId(id);

      ChannelPipeline cp = ctx.pipeline();

      LoggingHandler logHandler = cp.get(LoggingHandler.class);
      cp.remove(LoggingHandler.class);

      cp.addLast(new PacketDecoder(session),    /* First step for incoming packet - decode */
                 logHandler,                    /* In debug mode, second step for both incoming
                                                   & outgoing packet:
                                                   # if receiving, print the decoded packet in
                                                     hexadecimal format
                                                   # if sending, print the encoded packet in
                                                     hexadecimal format */
                 new ServerReqHandler(session), /* request handler */
                 new PacketEncoder(session));   /* First step for outgoing packet - encode */
      cp.remove(this);

      byte[] ki = IdExHandler.kexInit();
      session.setRawS2cKex(Bytes.concat(new byte[] {SshMessage.SSH_MSG_KEXINIT}, ki));

      session.sendKexInit(ki);

      if (accrued.readableBytes() > 0) {
        ctx.fireChannelRead(accrued);
      }
    }
    ReferenceCountUtil.release(msg);
  }
}
