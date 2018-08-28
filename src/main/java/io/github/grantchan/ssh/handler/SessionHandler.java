package io.github.grantchan.ssh.handler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ByteProcessor;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static io.github.grantchan.ssh.handler.SshConstant.MSG_KEX_COOKIE_SIZE;
import static io.github.grantchan.ssh.handler.SshConstant.SSH_MSG_KEXINIT;
import static io.github.grantchan.ssh.handler.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class SessionHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(SessionHandler.class);

  private final SecureRandom rand = new SecureRandom();

  private String clientVer = null;

  /*
   * RFC 4253:
   * Both the 'protoversion' and 'softwareversion' strings MUST consist of
   * printable US-ASCII characters, with the exception of whitespace
   * characters and the minus sign (-).
   */
  private final String serverVer = "SSH-2.0-DEMO";

  private ByteBuf accuBuf;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
    accuBuf = ctx.alloc().buffer();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
    accuBuf.release();
    accuBuf = null;
  }

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
    ctx.writeAndFlush(Unpooled.wrappedBuffer((serverVer + "\r\n").getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accuBuf.writeBytes((ByteBuf) msg);

    if (clientVer == null) {
      clientVer = getId(accuBuf);
      if (clientVer == null) {
        return;
      }
      ctx.pipeline().addLast(new PacketEncoder());

      ctx.channel().writeAndFlush(kexInit(ctx));
    }

    ReferenceCountUtil.release(msg);
  }

  /*
   * Get the remote peer's identification
   * @return the identification if successful, otherwise null.
   */
  protected String getId(final ByteBuf buf) {
    int rIdx = buf.readerIndex();
    int wIdx = buf.writerIndex();
    if (wIdx - rIdx <= 0) {
      return null;
    }

    int i = buf.forEachByte(rIdx, wIdx - rIdx, ByteProcessor.FIND_LF);
    if (i < 0) {
      return null;
    }

    int len = i - rIdx + 1;
    byte[] arr = new byte[len];
    buf.readBytes(arr);

    len--;
    if (arr[len - 1] == '\r') {
      len--;
    }

    buf.discardReadBytes();

    return new String(arr, 0, len, StandardCharsets.UTF_8);
  }

  /*
   * Construct the key exchange initialization packet.
   */
  private ByteBuf kexInit(ChannelHandlerContext ctx) {
    ByteBuf buf = ctx.alloc().buffer();

    buf.writerIndex(SSH_PACKET_HEADER_LENGTH);
    buf.readerIndex(SSH_PACKET_HEADER_LENGTH);
    buf.writeByte(SSH_MSG_KEXINIT);

    byte[] cookie = new byte[MSG_KEX_COOKIE_SIZE];
    rand.nextBytes(cookie);
    buf.writeBytes(cookie);

    writeUtf8(buf, "diffie-hellman-group-exchange-sha1");
    writeUtf8(buf, "ssh-rsa");
    writeUtf8(buf, "aes256-cbc" + "," + "aes256-ctr");
    writeUtf8(buf, "aes256-cbc" + "," + "aes256-ctr");
    writeUtf8(buf, "hmac-sha1");
    writeUtf8(buf, "hmac-sha1");
    writeUtf8(buf, "none");
    writeUtf8(buf, "none");
    writeUtf8(buf, "");
    writeUtf8(buf, "");

    buf.writeBoolean(false); // first kex packet follows
    buf.writeInt(0); // reserved (FFU)

    return buf;
  }

  private static int writeUtf8(ByteBuf buf, String val) {
    int idx = buf.writerIndex();

    buf.writeInt(val.length());
    buf.writeBytes(val.getBytes(StandardCharsets.UTF_8));

    return buf.writerIndex() - idx;
  }
}