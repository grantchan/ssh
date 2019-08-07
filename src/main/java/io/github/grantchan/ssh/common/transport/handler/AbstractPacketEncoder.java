package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.util.buffer.Bytes;
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
import java.util.Objects;

import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;

public abstract class AbstractPacketEncoder extends ChannelOutboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected final Session session;

  private final SecureRandom rand = new SecureRandom();
  private long seq = 0;

  public AbstractPacketEncoder(Session session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  protected abstract Cipher getCipher();

  protected abstract int getCipherSize();

  protected abstract Mac getMac();

  protected abstract int getMacSize();

  protected abstract int getDefMacSize();

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
    ByteBuf buf = (ByteBuf) msg;

    int len = buf.readableBytes();
    int off = buf.readerIndex() - SSH_PACKET_HEADER_LENGTH;

    // Calculate padding length
    int bsize  = getCipherSize();
    int oldLen = len;
    len += SSH_PACKET_HEADER_LENGTH;
    int pad = (-len) & (bsize - 1);
    if (pad < bsize) {
      pad += bsize;
    }
    len += pad - 4;

    // Write 5 header bytes
    buf.readerIndex(0);
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

    Mac mac = getMac();
    if (mac != null) {
      int macSize = getMacSize();
      mac.update(Bytes.htonl(seq));
      mac.update(packet);
      byte[] tmp = mac.doFinal();
      if (macSize != getDefMacSize()) {
        buf.writeBytes(tmp, 0, macSize);
      } else {
        buf.writeBytes(tmp);
      }
    }

    Cipher cipher = getCipher();
    if (cipher != null) {
      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, buf);
      logger.debug("[{}] Packet before encryption: \n{}", session, sb.toString());

      byte[] tmp = new byte[len + 4 - off];
      buf.getBytes(off, tmp);

      buf.setBytes(off, cipher.update(tmp));
    }

    seq = ++seq & 0xffffffffL;

    ctx.write(msg, promise);
  }
}
