package io.github.grantchan.ssh.server.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.handler.IdExHandler;
import io.github.grantchan.ssh.common.transport.handler.PacketDecoder;
import io.github.grantchan.ssh.common.transport.handler.PacketEncoder;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class SIdExHandler extends IdExHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected Session session;

  private ByteBuf accuBuf;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    session = new Session(ctx, true);
    accuBuf = session.createBuffer();
  }

  @Override
  protected Session getSession() {
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
    String sid = "SSH-2.0-Server DEMO";
    session.setServerId(sid);
    ctx.writeAndFlush(Unpooled.wrappedBuffer((sid + "\r\n").getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    accuBuf.writeBytes((ByteBuf) msg);

    String id = session.getClientId();
    if (id == null) {
      id = getId(accuBuf);
      if (id == null) {
        return;
      }

      logger.debug("received identification: {}", id);
      session.setClientId(id);

      ctx.pipeline().addLast(new PacketDecoder(session),
                             new SRequestHandler(session),
                             new PacketEncoder(session));
      ctx.pipeline().remove(this);

      ByteBuf serverKexInit = kexInit();
      byte[] buf = new byte[serverKexInit.readableBytes()];
      serverKexInit.getBytes(SSH_PACKET_HEADER_LENGTH, buf);
      session.setS2cKex(buf);

      ctx.channel().writeAndFlush(serverKexInit);

      if (accuBuf.readableBytes() > 0) {
        ctx.fireChannelRead(accuBuf);
      }
    }
    ReferenceCountUtil.release(msg);
  }
}
