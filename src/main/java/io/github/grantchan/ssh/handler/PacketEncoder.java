package io.github.grantchan.ssh.handler;

import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;

import static io.github.grantchan.ssh.common.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class PacketEncoder extends ChannelOutboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Session session;
  private final SecureRandom rand = new SecureRandom();

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
    int bsize  = 8;
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
    buf.writerIndex(off + oldLen + SSH_PACKET_HEADER_LENGTH);
    byte[] padding = new byte[pad];
    rand.nextBytes(padding);
    buf.writeBytes(padding);

    ctx.write(msg, promise);
  }
}

