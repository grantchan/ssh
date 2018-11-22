package io.github.grantchan.ssh.trans.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.util.buffer.ByteUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.SecureRandom;

import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class PacketEncoder extends ChannelOutboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Session session;
  private final SecureRandom rand = new SecureRandom();
  private long seq = 0;

  public PacketEncoder(Session session) {
    this.session = session;
  }

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
      throws Exception {
    ByteBuf buf = (ByteBuf) msg;

    int len = buf.readableBytes();
    int off = buf.readerIndex() - SSH_PACKET_HEADER_LENGTH;

    // Calculate padding length
    int bsize  = session.getS2cCipherSize();
    int oldLen = len;
    len += SSH_PACKET_HEADER_LENGTH;
    int pad = (-len) & (bsize - 1);
    if (pad < bsize) {
      pad += bsize;
    }
    len += pad - 4;

    // Write 5 header bytes
    buf.readerIndex(off);
    buf.writerIndex(off);
    buf.writeInt(len);
    buf.writeByte(pad);

    // Fill padding
    buf.writerIndex(off + SSH_PACKET_HEADER_LENGTH + oldLen);
    byte[] padding = new byte[pad];
    rand.nextBytes(padding);
    buf.writeBytes(padding);

    byte[] packet = new byte[buf.readableBytes()];
    buf.getBytes(off, packet);

    Mac s2cMac = session.getS2cMac();
    if (s2cMac != null) {
      int macSize = session.getS2cMacSize();
      s2cMac.update(ByteUtil.htonl(seq));
      s2cMac.update(packet);
      byte[] tmp = s2cMac.doFinal();
      if (macSize != session.getS2cDefMacSize()) {
        buf.writeBytes(tmp, 0, macSize);
      } else {
        buf.writeBytes(tmp);
      }
    }

    Cipher s2cCipher = session.getS2cCipher();
    if (s2cCipher != null) {
      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, buf);
      logger.debug("Packet before encryption: \n{}", sb.toString());

      byte[] tmp = new byte[len + 4 - off];
      buf.getBytes(off, tmp);

      buf.setBytes(off, s2cCipher.update(tmp));
    }

    seq = ++seq & 0xffffffffL;

    ctx.write(msg, promise);
  }
}