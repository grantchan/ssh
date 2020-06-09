package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.util.buffer.Bytes;
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
import java.util.concurrent.atomic.AtomicLong;

public class PacketEncoder extends ChannelOutboundHandlerAdapter
                           implements SessionHolder {

  private static final Logger logger = LoggerFactory.getLogger(PacketEncoder.class);

  private static final SecureRandom rand = new SecureRandom();

  private final AbstractSession session;

  /** Packet sequence number */
  private AtomicLong seq = new AtomicLong(0);

  /** Total number of bytes of the packet sent */
  private AtomicLong bytesOfPacket = new AtomicLong(0);

  /** Total number of bytes of compressed data sent */
  private AtomicLong bytesOfZippedData = new AtomicLong(0);

  /** Total number of bytes of uncompressed data sent or data before being compressed */
  private AtomicLong bytesOfData = new AtomicLong(0);

  public PacketEncoder(AbstractSession session) {
    this.session = session;
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
    ByteBuf buf = encode((ByteBuf) msg);

    ctx.write(buf, promise);
  }

  private ByteBuf encode(ByteBuf msg) {
    int len = msg.readableBytes();
    int off = msg.readerIndex() - SshConstant.SSH_PACKET_HEADER_LENGTH;

    bytesOfData.addAndGet(len);

    Compression comp = session.getOutCompression();
    if (comp != null && session.isAuthed() && len > 0) {
      byte[] plain = new byte[len];
      msg.readBytes(plain);

      msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
      msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);

      byte[] zipped = comp.compress(plain);
      logger.debug("[{}] Compressed packet: ({} -> {} bytes)", session, plain.length,
          zipped.length);

      msg.writeBytes(zipped);
      len = msg.readableBytes();

      bytesOfZippedData.addAndGet(len);
    }

    // Calculate padding length
    int blkSize  = session.getOutCipherBlkSize();
    int oldLen = len;
    len += SshConstant.SSH_PACKET_HEADER_LENGTH;
    int pad = (-len) & (blkSize - 1);
    if (pad < blkSize) {
      pad += blkSize;
    }
    len += pad - 4;

    // Write 5 header bytes
    msg.readerIndex(0);
    msg.writerIndex(off);
    msg.writeInt(len);
    msg.writeByte(pad);

    // Fill padding
    msg.writerIndex(off + SshConstant.SSH_PACKET_HEADER_LENGTH + oldLen);
    byte[] padding = new byte[pad];
    rand.nextBytes(padding);
    msg.writeBytes(padding);

    byte[] packet = new byte[msg.readableBytes()];
    msg.getBytes(off, packet);

    Mac mac = session.getOutMac();
    if (mac != null) {
      int macSize = session.getOutMacSize();
      mac.update(Bytes.toBigEndian(seq.get()));
      mac.update(packet);
      byte[] tmp = mac.doFinal();
      if (macSize != session.getOutDefMacSize()) {
        msg.writeBytes(tmp, 0, macSize);
      } else {
        msg.writeBytes(tmp);
      }
    }

    Cipher cipher = session.getOutCipher();
    if (cipher != null) {
      if (logger.isDebugEnabled()) {
        StringBuilder sb = new StringBuilder();
        ByteBufUtil.appendPrettyHexDump(sb, msg);
        logger.debug("[{}] Packet before encryption: \n{}", session, sb.toString());
      }

      byte[] tmp = new byte[len + 4 - off];
      msg.getBytes(off, tmp);

      msg.setBytes(off, cipher.update(tmp));
    }

    seq.incrementAndGet();

    bytesOfPacket.addAndGet(msg.readableBytes());

    return msg;
  }
}
