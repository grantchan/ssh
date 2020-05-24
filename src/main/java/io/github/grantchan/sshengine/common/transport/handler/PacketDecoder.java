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

import static io.github.grantchan.sshengine.arch.SshConstant.SSH_PACKET_LENGTH;

public class PacketDecoder extends ChannelInboundHandlerAdapter
                                   implements SessionHolder {

  private static final Logger logger = LoggerFactory.getLogger(PacketDecoder.class);

  private final AbstractSession session;

  private ByteBuf accrued;

  private AtomicInteger step = new AtomicInteger(0);
  private AtomicLong seq = new AtomicLong(0); // packet sequence number

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
    while (accrued.readableBytes() > blkSize &&
           (packet = decode(accrued)) != null) {  // received packet should be bigger than a block
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
   * @return the message decoded from the packet, if successful, otherwise null,
   * the accumulate packet buffer remains unchanged.
   */
  private ByteBuf decode(ByteBuf msg) throws Exception {
    int rIdx = msg.readerIndex();
    byte[] buf = new byte[msg.readableBytes()];
    msg.getBytes(rIdx, buf);

    AbstractSession session = getSession();

    Cipher cipher = session.getInCipher();
    int blkSize = session.getInCipherBlkSize();

    //
    // Two decode steps here:
    // 1. decode the first block of the packet, the size of a block is the cipher size. In the
    //    first block, we check if the packet is fully received, if yes, we move on to step 2,
    //    otherwise, return null.
    // 2. decode the rest of the buffer
    //

    if (step.get() == 0 && cipher != null) {
      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, msg);
      logger.debug("[{}] Encrypted packet received: \n{}", session, sb.toString());

      // decrypt the first block of the packet
      msg.setBytes(rIdx, cipher.update(buf, 0, blkSize));

      step.set(1);
    }

    // Since the size of a block must be bigger than the size of an integer, as long as the first
    // block has been decrypted(or in plain text), we must be able to read the first integer,
    // which indicates the size of the packet.
    int len = msg.readInt();

    if (len < SshConstant.SSH_PACKET_HEADER_LENGTH || len > SshConstant.SSH_PACKET_MAX_LENGTH) {
      // It's an invalid packet if it's less than 5 bytes or bigger than 256k bytes
      logger.error("[{}] Illegal packet to decode - invalid packet length: {}", session, len);

      throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
          "Invalid packet length: " + len);
    }

    int macSize = session.getInMacSize();

    // Integrity check
    // we check the size of unread bytes to see whether it's a segment. If yes, we quit here.
    if (msg.readableBytes() < len + macSize) {
      // packet has not been fully received, restore the reader pointer
      msg.readerIndex(rIdx);
      return null;
    }

    // Here comes step 2 mentioned above - decrypts the remaining blocks of the packet
    if (cipher != null) {
      // The first block has been already decrypted, we figure out the size of the rest by:
      // 1. recovering the full size of the packet: len + SSH_PACKET_LENGTH,
      // 2. subtracting a block size
      int cipLen = SSH_PACKET_LENGTH + len - blkSize;
      if (cipLen > 0) {
        msg.setBytes(rIdx + blkSize, cipher.update(buf, rIdx + blkSize, cipLen));
      }
    }

    byte[] macBlk = new byte[macSize];

    // The packet is fully decrypted here, we verify its integrity by the MAC
    Mac mac = session.getInMac();
    if (mac != null) {
      mac.update(Bytes.toBigEndian(seq.get()));

      byte[] decryptedPacket = new byte[SSH_PACKET_LENGTH + len];
      msg.getBytes(rIdx, decryptedPacket);
      mac.update(decryptedPacket, 0, SSH_PACKET_LENGTH + len);
      mac.doFinal(macBlk, 0);

      int i = macSize, j = 0, k = SSH_PACKET_LENGTH + len;
      // Go through the MAC segment, which is at the end of the packet, to verify
      while (i-- > 0) {
        if (macBlk[j++] != buf[k++]) {
          logger.error("[{}] Failed to verify the packet at position: {}", session, k - 1);

          throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR, "MAC Error");
        }
      }
    }

    seq.set(seq.incrementAndGet() & 0xffffffffL);

    int pad = msg.readByte() & 0xFF;
    len -= (Byte.BYTES + pad);

    ByteBuf packet;

    Compression compression = session.getInCompression();
    if (compression != null && session.isAuthed() && len > 0) {
      byte[] zipped = new byte[len];
      msg.readBytes(zipped);
      byte[] unzipped = compression.decompress(zipped);

      packet = session.createBuffer(unzipped.length);

      packet.writeBytes(unzipped);

      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, packet);
      logger.debug("[{}] Decompressed packet ({} -> {} bytes): \n{}", session, zipped.length,
          unzipped.length, sb.toString());
    } else {
      packet = session.createBuffer(len);

      msg.readBytes(packet);
    }

    msg.skipBytes(pad + macSize);

    step.set(0);

    return packet;
  }
}
