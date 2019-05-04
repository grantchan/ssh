package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
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

public class PacketDecoder extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Session session;

  private ByteBuf accuBuf;
  private int decodeStep = 0;
  private long seq = 0; // packet sequence number

  public PacketDecoder(Session session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    accuBuf = session.createBuffer();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) {
    ReferenceCountUtil.release(accuBuf);
    accuBuf = null;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accuBuf.writeBytes((ByteBuf) msg);

    boolean isServer = session.isServer();

    int cipherSize = isServer ? session.getC2sCipherSize() : session.getS2cCipherSize();
    while (accuBuf.readableBytes() > cipherSize) {
      int wIdx = accuBuf.writerIndex();

      int pkLen = decode();
      if (pkLen != -1) {
        // This is important - handling the SSH_MSG_NEWKEYS will update the MAC block size,
        // we need to cache this value and use it until the message is fully process.
        int macSize = isServer ? session.getC2sMacSize() : session.getC2sMacSize();

        ctx.fireChannelRead(accuBuf);

        // restore the writer index, and update reader index to the start of next packet
        accuBuf.writerIndex(wIdx);
        accuBuf.readerIndex(pkLen + SSH_PACKET_LENGTH + macSize);

        accuBuf.discardReadBytes();
      } else {
        break;
      }
    }
    ReferenceCountUtil.release(msg);
  }

  /*
   * Decode the incoming buffer.
   *
   * @return the length of the packet fully contains the message if successful,otherwise -1,
   * the accumulate buffer remains unchanged.
   */
  private int decode() throws Exception {
    int rIdx = accuBuf.readerIndex();
    byte[] packet = new byte[accuBuf.readableBytes()];
    accuBuf.getBytes(rIdx, packet);

    boolean isServer = session.isServer();

    Cipher cipher = isServer ? session.getC2sCipher() : session.getS2cCipher();
    int cipherSize = isServer ? session.getC2sCipherSize() : session.getS2cCipherSize();
    if (decodeStep == 0 && cipher != null) {
      if (!isServer) {
        StringBuilder sb = new StringBuilder();
        ByteBufUtil.appendPrettyHexDump(sb, accuBuf);
        logger.debug("[{}] Encrypted packet received: \n{}", session, sb.toString());
      }

      // decrypt the first block of the packet
      accuBuf.setBytes(rIdx, cipher.update(packet, 0, cipherSize));

      decodeStep = 1;
    }

    int len  = accuBuf.readInt();
    if (len < SshConstant.SSH_PACKET_HEADER_LENGTH || len > SshConstant.SSH_PACKET_MAX_LENGTH) {
      logger.error("[{}] Illegal packet to decode - invalid packet length: {}", session, len);

      throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
          "Invalid packet length: " + len);
    }

    int macSize = isServer ? session.getC2sMacSize() : session.getS2cMacSize();

    // integrity check
    if (accuBuf.readableBytes() < len + macSize) {
      // packet has not been fully received, restore the reader pointer
      accuBuf.readerIndex(rIdx);
      return -1;
    }

    // decrypt the remaining blocks of the packet
    if (cipher != null) {
      int cipLen = len + SSH_PACKET_LENGTH - cipherSize;
      if (cipLen > 0) {
        accuBuf.setBytes(rIdx + cipherSize,
            cipher.update(packet, rIdx + cipherSize, cipLen));
      }

      if (isServer) {
        StringBuilder sb = new StringBuilder();
        ByteBufUtil.appendPrettyHexDump(sb, accuBuf);
        logger.debug("[{}] Decrypted packet: \n{}", session, sb.toString());
      }

      int i = accuBuf.readerIndex();
      accuBuf.readerIndex(i - SSH_PACKET_LENGTH);
      accuBuf.readerIndex(i);
    }

    // verify the packet by the MAC
    Mac mac = isServer ? session.getC2sMac() : session.getS2cMac();
    if (mac != null) {
      mac.update(Bytes.htonl(seq));

      byte[] decryptedPacket = new byte[len + SSH_PACKET_LENGTH];
      accuBuf.getBytes(rIdx, decryptedPacket);
      mac.update(decryptedPacket, 0, len + SSH_PACKET_LENGTH);
      byte[] blk = new byte[macSize];
      mac.doFinal(blk, 0);

      int i = 0, j = len + SSH_PACKET_LENGTH;
      while (macSize-- > 0) {
        if (blk[i++] != packet[j++]) {
          logger.error("[{}] Failed to verify the packet at position: {}", session, j - 1);

          throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR, "MAC Error");
        }
      }
    }
    seq = (++seq) & 0xffffffffL;

    int pad = accuBuf.readByte() & 0xFF;
    accuBuf.writerIndex(len + SSH_PACKET_LENGTH - pad);

    decodeStep = 0;

    return len;
  }
}
