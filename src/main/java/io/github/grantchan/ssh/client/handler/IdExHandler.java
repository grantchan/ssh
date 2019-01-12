package io.github.grantchan.ssh.client.handler;

import io.github.grantchan.ssh.common.transport.handler.PacketDecoder;
import io.github.grantchan.ssh.common.transport.handler.PacketEncoder;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public class IdExHandler extends io.github.grantchan.ssh.common.transport.handler.IdExHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

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
    session.setClientId("SSH-2.0-Client DEMO");
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    super.channelRead(ctx, msg);

    String id = session.getServerId();
    if (id == null) {
      id = getId();
      if (id == null) {
        return;
      }

      logger.debug("received identification: {}", id);
      session.setServerId(id);

      ctx.pipeline().addLast(new PacketDecoder(session),
                             new RequestHandler(session),
                             new PacketEncoder(session));
      ctx.pipeline().remove(this);

      String cid = session.getClientId();
      ctx.writeAndFlush(Unpooled.wrappedBuffer((cid + "\r\n").getBytes(StandardCharsets.UTF_8)));

      // kex init
    }

    ReferenceCountUtil.release(msg);
  }
}
