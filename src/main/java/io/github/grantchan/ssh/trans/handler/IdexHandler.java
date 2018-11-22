package io.github.grantchan.ssh.trans.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.cipher.BuiltinCipherFactory;
import io.github.grantchan.ssh.trans.compression.BuiltinCompressionFactory;
import io.github.grantchan.ssh.trans.kex.BuiltinKexHandlerFactory;
import io.github.grantchan.ssh.trans.mac.BuiltinMacFactory;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ByteProcessor;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static io.github.grantchan.ssh.arch.SshConstant.MSG_KEX_COOKIE_SIZE;
import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;
import static io.github.grantchan.ssh.arch.SshMessage.SSH_MSG_KEXINIT;

public class IdexHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  /*
   * RFC 4253: The maximum length of the string is 255 characters,
   * including the Carriage Return and Line Feed.
   */
  private final int MAX_IDENTIFICATION_LINE_LENGTH = 255;

  private final SecureRandom rand = new SecureRandom();

  protected Session session;
  protected ByteBuf accuBuf;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
    session = new Session(ctx);
    accuBuf = ctx.alloc().buffer();
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
    String sid = session.getServerVer();
    ctx.writeAndFlush(Unpooled.wrappedBuffer((sid + "\r\n").getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accuBuf.writeBytes((ByteBuf) msg);

    String clientVer = session.getClientVer();
    if (clientVer == null) {
      clientVer = getClientId();
      if (clientVer == null) {
        return;
      }

      logger.debug("received identification: {}", clientVer);
      session.setClientVer(clientVer);

      ctx.pipeline().addLast(new PacketDecoder(session),
                             new RequestHandler(session),
                             new PacketEncoder(session));
      ctx.pipeline().remove(this);

      ByteBuf serverKexInit = kexInit(ctx);
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
   * Get the remote peer's identification
   * @return the identification if successful, otherwise null.
   */
  String getClientId() {
    int rIdx = accuBuf.readerIndex();
    int wIdx = accuBuf.writerIndex();
    if (rIdx == wIdx) {
      return null;
    }

    final String[] id = {null};

    ByteProcessor findId = new ByteProcessor() {
      private int line = 1, pos = 0;
      private boolean needLf = false;
      private boolean validLine = false;

      private byte[] data = new byte[MAX_IDENTIFICATION_LINE_LENGTH];

      @Override
      public boolean process(byte b) throws Exception {

        /* RFC 4253: The null character MUST NOT be sent. */
        if (b == '\0') {
          throw new IllegalStateException("Illegal identification - null character found at" +
                                          " line #" + line + " character #" + pos + 1);
        }

        if (b == '\r') {
          needLf = true;
          return true;
        }

        if (b == '\n') {
          line++;

          if (validLine) {
            id[0] = new String(data, 0, pos, StandardCharsets.UTF_8);
            return false;
          }
          pos = 0;
          needLf = false;
          return true;
        }

        if (needLf) {
          throw new IllegalStateException("Illegal identification - invalid line ending at" +
                                          " line #" + line + " character #" + pos + 1);
        }

        if (pos > data.length) {
          throw new IllegalStateException("Illegal identification - line too long at" +
                                          " line #" + line + " character #" + pos + 1);
        }

        if (pos < 4) {
          data[pos++] = b;
        } else if (data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-') {
          validLine = true;
          data[pos++] = b;
        }

        return true;
      }
    };

    int i = accuBuf.forEachByte(rIdx, wIdx - rIdx, findId);
    if (i == -1) {
      // packet is not fully received, restore reader index and return
      accuBuf.readerIndex(rIdx);
      return null;
    }

    accuBuf.readerIndex(i + 1);
    accuBuf.discardReadBytes();

    return id[0];
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

    ByteBufUtil.writeUtf8(buf, BuiltinKexHandlerFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinSignatureFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinCipherFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinCipherFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinMacFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinMacFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinCompressionFactory.getNames());
    ByteBufUtil.writeUtf8(buf, BuiltinCompressionFactory.getNames());
    ByteBufUtil.writeUtf8(buf, "");
    ByteBufUtil.writeUtf8(buf, "");

    buf.writeBoolean(false); // first factory packet follows
    buf.writeInt(0); // reserved (FFU)

    return buf;
  }
}
