package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.compression.Compression;
import io.github.grantchan.ssh.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.Objects;

import static io.github.grantchan.ssh.arch.SshConstant.SSH_PACKET_LENGTH;

public abstract class AbstractPacketDecoder extends ChannelInboundHandlerAdapter
                                            implements SessionHolder {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private ByteBuf accrued;
  private ByteBuf packet;

  private int decodeStep = 0;
  private long seq = 0; // packet sequence number

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");
    accrued = session.createBuffer();
    packet = session.createBuffer();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) {
    ReferenceCountUtil.release(packet);
    packet = null;

    ReferenceCountUtil.release(accrued);
    accrued = null;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accrued.writeBytes((ByteBuf) msg);

    int blkSize = getBlkSize();
    while (accrued.readableBytes() > blkSize && decode()) {  // received packet should be bigger
                                                             // than a block
      ctx.fireChannelRead(packet);

      accrued.discardReadBytes();
    }
    ReferenceCountUtil.release(msg);
  }

  protected abstract Cipher getCipher();

  protected abstract int getBlkSize();

  protected abstract Mac getMac();

  protected abstract int getMacSize();

  protected abstract Compression getCompression();

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
  private boolean decode() throws Exception {
    int rIdx = accrued.readerIndex();
    byte[] buf = new byte[accrued.readableBytes()];
    accrued.getBytes(rIdx, buf);

    Cipher cipher = getCipher();
    int cipherSize = getBlkSize();

    //
    // Two decode steps here:
    // 1. decode the first block of the packet, the size of a block is the cipher size. In the
    //    first block, we check if the packet is fully received, if yes, we move on to step 2,
    //    otherwise, return null.
    // 2. decode the rest of the buffer
    //

    if (decodeStep == 0 && cipher != null) {
      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, accrued);
      logger.debug("[{}] Encrypted packet received: \n{}", getSession(), sb.toString());

      // decrypt the first block of the packet
      accrued.setBytes(rIdx, cipher.update(buf, 0, cipherSize));

      decodeStep = 1;
    }

    // Since the size of a block must be bigger than the size of an integer, as long as the first
    // block has been decrypted(or in plain text), we must be able to read the first integer,
    // which indicates the size of the packet.
    int len = accrued.readInt();

    if (len < SshConstant.SSH_PACKET_HEADER_LENGTH || len > SshConstant.SSH_PACKET_MAX_LENGTH) {
      // It's an invalid packet if it's less than 5 bytes or bigger than 256k bytes
      logger.error("[{}] Illegal packet to decode - invalid packet length: {}", getSession(), len);

      throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
          "Invalid packet length: " + len);
    }

    int macSize = getMacSize();

    // Integrity check
    // we check the size of unread bytes to see whether it's a segment. If yes, we quit here.
    if (accrued.readableBytes() < len + macSize) {
      // packet has not been fully received, restore the reader pointer
      accrued.readerIndex(rIdx);
      return false;
    }

    // Here comes step 2 mentioned above - decrypts the remaining blocks of the packet
    if (cipher != null) {
      // The first block has been already decrypted, we figure out the size of the rest by:
      // 1. recovering the full size of the packet: len + SSH_PACKET_LENGTH,
      // 2. subtracting a block size
      int cipLen = SSH_PACKET_LENGTH + len - cipherSize;
      if (cipLen > 0) {
        accrued.setBytes(rIdx + cipherSize,
            cipher.update(buf, rIdx + cipherSize, cipLen));
      }
    }

    byte[] macBlk = new byte[macSize];

    // The packet is fully decrypted here, we verify its integrity by the MAC
    Mac mac = getMac();
    if (mac != null) {
      mac.update(Bytes.htonl(seq));

      byte[] decryptedPacket = new byte[SSH_PACKET_LENGTH + len];
      accrued.getBytes(rIdx, decryptedPacket);
      mac.update(decryptedPacket, 0, SSH_PACKET_LENGTH + len);
      mac.doFinal(macBlk, 0);

      int i = macSize, j = 0, k = SSH_PACKET_LENGTH + len;
      // Go through the MAC segment, which is at the end of the packet, to verify
      while (i-- > 0) {
        if (macBlk[j++] != buf[k++]) {
          logger.error("[{}] Failed to verify the packet at position: {}", getSession(), k - 1);

          throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR, "MAC Error");
        }
      }
    }

    seq = (++seq) & 0xffffffffL;

    int pad = accrued.readByte() & 0xFF;
    len -= (Byte.BYTES + pad);

    packet.clear();

    Compression compression = getCompression();
    if (compression != null && getSession().isAuthed() && len > 0) {
      byte[] zipped = new byte[len];
      accrued.readBytes(zipped);
      byte[] unzipped = compression.decompress(zipped);

      packet.capacity(unzipped.length);

      packet.writeBytes(unzipped);

      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, packet);
      logger.debug("[{}] Decompressed packet ({} -> {} bytes): \n{}",
          getSession(), zipped.length, unzipped.length, sb.toString());
    } else {
      packet.capacity(len);

      accrued.readBytes(packet);
    }

    accrued.skipBytes(pad + macSize);

    decodeStep = 0;

    return true;
  }
}
