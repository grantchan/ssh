package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.handler.IdExHandler;
import io.github.grantchan.ssh.common.transport.handler.PacketDecoder;
import io.github.grantchan.ssh.common.transport.handler.PacketEncoder;
import io.github.grantchan.ssh.common.transport.handler.RequestHandler;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class IdExClient extends ChannelInboundHandlerAdapter implements IdExHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected Session session;

  private ByteBuf accuBuf;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    session = new Session(ctx, false);
    accuBuf = session.createBuffer();
  }

  @Override
  public Session getSession() {
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
    session.setClientId("SSH-2.0-Client DEMO");
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    accuBuf.writeBytes((ByteBuf) msg);

    String id = session.getServerId();
    if (id == null) {
      id = IdExHandler.getId(accuBuf);
      if (id == null) {
        return;
      }

      logger.debug("Received identification: {}", id);
      session.setServerId(id);

      ctx.pipeline().addLast(new PacketDecoder(session),
                             new RequestHandler(session),
                             new PacketEncoder(session));
      ctx.pipeline().remove(this);

      ByteBuf ki = kexInit();
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
    }

    ReferenceCountUtil.release(msg);
  }
}
