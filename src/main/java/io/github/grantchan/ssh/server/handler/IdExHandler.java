package io.github.grantchan.ssh.server.handler;

import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.common.transport.compression.CompressionFactories;
import io.github.grantchan.ssh.common.transport.handler.PacketDecoder;
import io.github.grantchan.ssh.common.transport.handler.PacketEncoder;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.trans.kex.BuiltinKexHandlerFactory;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static io.github.grantchan.ssh.arch.SshConstant.MSG_KEX_COOKIE_SIZE;
import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;
import static io.github.grantchan.ssh.arch.SshMessage.SSH_MSG_KEXINIT;

public class IdExHandler extends io.github.grantchan.ssh.common.transport.handler.IdExHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final SecureRandom rand = new SecureRandom();

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
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
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    super.channelRead(ctx, msg);

    String id = session.getClientId();
    if (id == null) {
      id = getId();
      if (id == null) {
        return;
      }

      logger.debug("received identification: {}", id);
      session.setClientId(id);

      ctx.pipeline().addLast(new PacketDecoder(session),
                             new RequestHandler(session),
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


  /*
   * Construct the key exchange initialization packet.
   */
  private ByteBuf kexInit() {
    ByteBuf buf = session.createBuffer();

    buf.writerIndex(SSH_PACKET_HEADER_LENGTH);
    buf.readerIndex(SSH_PACKET_HEADER_LENGTH);
    buf.writeByte(SSH_MSG_KEXINIT);

    byte[] cookie = new byte[MSG_KEX_COOKIE_SIZE];
    rand.nextBytes(cookie);
    buf.writeBytes(cookie);

    ByteBufUtil.writeUtf8(buf, BuiltinKexHandlerFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinSignatureFactory.getNames());
    ByteBufUtil.writeUtf8(buf, CipherFactories.getNames());
    ByteBufUtil.writeUtf8(buf, CipherFactories.getNames());
    ByteBufUtil.writeUtf8(buf, MacFactories.getNames());
    ByteBufUtil.writeUtf8(buf, MacFactories.getNames());
    ByteBufUtil.writeUtf8(buf, CompressionFactories.getNames());
    ByteBufUtil.writeUtf8(buf, CompressionFactories.getNames());
    ByteBufUtil.writeUtf8(buf, "");
    ByteBufUtil.writeUtf8(buf, "");

    buf.writeBoolean(false); // first factory packet follows
    buf.writeInt(0); // reserved (FFU)

    return buf;
  }
}
