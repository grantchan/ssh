package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class PacketDecoder extends ChannelInboundHandlerAdapter
                                   implements SessionHolder {

  private static final Logger logger = LoggerFactory.getLogger(PacketDecoder.class);

  private final AbstractSession session;

  private ByteBuf accrued;

 /**
  * An indicator remembers which decoding step is currently at.
  *
  * There are two decode steps:
  * 1. decode the first block of the packet, the size of a block is the cipher size.
  *    In the first block, we check if the packet is fully received, if yes, we move on to step 2,
  *    otherwise, return null.
  * 2. decode the rest of the buffer
  */
  private AtomicInteger step = new AtomicInteger(0);

  /** Packet sequence number */
  private AtomicLong seq = new AtomicLong(0);

  /** Total number of bytes of packets received */
  private AtomicLong bytesOfPacket = new AtomicLong(0);

  /** Total number of bytes of the compressed data received */
  private AtomicLong bytesOfZippedData = new AtomicLong(0);

  /** Total number of bytes of uncompressed data received or data after being uncompressed */
  private AtomicLong bytesOfData = new AtomicLong(0);

  public PacketDecoder(AbstractSession session) {
    this.session = session;
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    accrued = session.createBuffer();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) {
    ReferenceCountUtil.release(accrued);
    accrued = null;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accrued.writeBytes((ByteBuf) msg);

    int blkSize = getSession().getInCipherBlkSize();

    ByteBuf packet;

    // Received packet must be bigger than a block
    while (accrued.readableBytes() > blkSize && (packet = decode(accrued)) != null) {
      ctx.fireChannelRead(packet);

      accrued.discardReadBytes();
    }
    ReferenceCountUtil.release(msg);
  }

  /**
   * Decode the incoming SSH packet.
   *
   * <pre>
   *
   *                     |<- - - - - - - -   packet   - - - - - - - - - ->|
   * | packet size (int) | padding size (byte) |<- -  DATA  - ->| padding | MAC block |
   *
   * </pre>
   *
   * @return the message data decoded from the packet, if successful, otherwise null,
   * the accumulate packet buffer remains unchanged.
   */
  private ByteBuf decode(ByteBuf msg) throws Exception {
    int rIdx = msg.readerIndex();
    byte[] buf = new byte[msg.readableBytes()];
    msg.getBytes(rIdx, buf);

    AbstractSession session = getSession();

    Cipher cipher = session.getInCipher();
    int blkSize = session.getInCipherBlkSize();

    // Decrypt the first block if necessary
    if (step.get() == 0 && cipher != null) {
      if (logger.isDebugEnabled()) {
        StringBuilder sb = new StringBuilder();
        ByteBufUtil.appendPrettyHexDump(sb, msg);
        logger.debug("[{}] Encrypted packet received: \n{}", session, sb.toString());
      }

      // Decrypt the first block of the packet
      msg.setBytes(rIdx, cipher.update(buf, 0, blkSize));

      step.set(1);
    }

    // It's guaranteed before getting here that the size of a message must be bigger than
    // the size of an integer.
    // Either the first block has been decrypted, or it's in plain text - cipher hasn't been
    // negotiated, we must be able to read the first integer, which indicates the size of
    // the packet.
    int len = msg.readInt();

    // It's an invalid packet if it's less than 5 bytes or bigger than 256k bytes
    if (len < SshConstant.SSH_PACKET_HEADER_LENGTH || len > SshConstant.SSH_PACKET_MAX_LENGTH) {
      logger.error("[{}] Illegal packet to decode - invalid packet length: {}", session, len);

      throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
          "Invalid packet length: " + len);
    }

    int macSize = session.getInMacSize();

    // Integrity check - checking the size of unread bytes to see whether it's a segment.
    // If yes, meaning the packet has not been fully received, quit here.
    if (msg.readableBytes() < len + macSize) {
      // restore the reader pointer
      msg.readerIndex(rIdx);

      return null;
    }

    bytesOfPacket.addAndGet(buf.length);

    // Here comes step 2 mentioned above - decrypts the remaining blocks of the packet
    if (cipher != null) {
      // The first block has been already decrypted, we figure out the size of the rest by:
      // 1. recovering the full size of the packet: len + SSH_PACKET_LENGTH,
      // 2. subtracting a block size
      int cipLen = SshConstant.SSH_PACKET_LENGTH + len - blkSize;
      if (cipLen > 0) {
        msg.setBytes(rIdx + blkSize, cipher.update(buf, rIdx + blkSize, cipLen));
      }
    }

    byte[] macBlk = new byte[macSize];

    // The packet is fully decrypted here, we verify its integrity by the MAC
    Mac mac = session.getInMac();
    if (mac != null) {
      mac.update(Bytes.toBigEndian(seq.get()));

      byte[] decryptedPacket = new byte[SshConstant.SSH_PACKET_LENGTH + len];
      msg.getBytes(rIdx, decryptedPacket);
      mac.update(decryptedPacket, 0, SshConstant.SSH_PACKET_LENGTH + len);
      mac.doFinal(macBlk, 0);

      int i = macSize, j = 0, k = SshConstant.SSH_PACKET_LENGTH + len;
      // Go through the MAC segment, which is at the end of the packet, to verify
      while (i-- > 0) {
        if (macBlk[j++] != buf[k++]) {
          logger.error("[{}] Failed to verify the packet at position: {}", session, k - 1);

          throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR, "MAC Error");
        }
      }
    }

    seq.incrementAndGet();

    int pad = msg.readByte() & 0xFF;
    len -= (Byte.BYTES + pad);

    ByteBuf data;

    Compression compression = session.getInCompression();
    if (compression != null && session.isAuthed() && len > 0) {
      byte[] zipped = new byte[len];
      bytesOfZippedData.addAndGet(len);

      msg.readBytes(zipped);
      byte[] unzipped = compression.decompress(zipped);
      bytesOfData.addAndGet(unzipped.length);

      data = session.createBuffer(unzipped.length);
      data.writeBytes(unzipped);

      if (logger.isDebugEnabled()) {
        StringBuilder sb = new StringBuilder();
        ByteBufUtil.appendPrettyHexDump(sb, data);
        logger.debug("[{}] Decompressed packet ({} -> {} bytes): \n{}", session, zipped.length,
            unzipped.length, sb.toString());
      }
    } else {
      data = session.createBuffer(len);

      msg.readBytes(data);

      bytesOfData.addAndGet(len);
    }

    msg.skipBytes(pad + macSize); // skip padding & integration check data

    step.set(0);

    return data;
  }
}
