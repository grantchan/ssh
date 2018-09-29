package io.github.grantchan.ssh.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshConstant;
import io.github.grantchan.ssh.util.ByteUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import java.io.IOException;

import static io.github.grantchan.ssh.common.SshConstant.SSH_PACKET_LENGTH;

public class PacketDecoder extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Session session;

  protected ByteBuf accuBuf;
  private int decodeStep = 0;
  private long seq = 0; // packet sequence number

  public PacketDecoder(Session session) {
    this.session = session;
  }

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
    accuBuf = ctx.alloc().buffer();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
    ReferenceCountUtil.release(accuBuf);
    accuBuf = null;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accuBuf.writeBytes((ByteBuf) msg);

    int c2sCipSize = session.getC2sCipherSize();
    while (accuBuf.readableBytes() > c2sCipSize) {
      int wIdx = accuBuf.writerIndex();

      int pkLen = decode();
      if (pkLen != -1) {
        // This is important - handling the SSH_MSG_NEWKEYS will update the MAC block size,
        // we need to cache this value and use it until the message is fully process.
        int macSize = session.getC2sMacSize();

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

    Cipher c2sCip = session.getC2sCipher();
    int c2sCipSize = session.getC2sCipherSize();
    if (decodeStep == 0 && c2sCip != null) {
      // decrypt the first block of the packet
      accuBuf.setBytes(rIdx, c2sCip.update(packet, 0, c2sCipSize));

      decodeStep = 1;
    }

    int len  = accuBuf.readInt();

    int c2sMacSize = session.getC2sMacSize();
    if (accuBuf.readableBytes() < len + c2sMacSize) {
      // packet has not been fully received, restore the reader pointer
      accuBuf.readerIndex(rIdx);
      return -1;
    }

    // decrypt the remaining blocks of the packet
    if (c2sCip != null) {
      accuBuf.setBytes(rIdx + c2sCipSize,
          c2sCip.update(packet, rIdx + c2sCipSize, len + SSH_PACKET_LENGTH - c2sCipSize));

      StringBuilder sb = new StringBuilder();
      int i = accuBuf.readerIndex();
      accuBuf.readerIndex(i - SSH_PACKET_LENGTH);
      ByteBufUtil.appendPrettyHexDump(sb, accuBuf);
      logger.debug("Decrypted packet: \n{}", sb.toString());
      accuBuf.readerIndex(i);
    }

    // verify the packet by the MAC
    Mac c2sMac = session.getC2sMac();
    if (c2sMac != null) {
      c2sMac.update(ByteUtil.htonl(seq));

      byte[] decryptedPacket = new byte[len + SSH_PACKET_LENGTH];
      accuBuf.getBytes(rIdx, decryptedPacket);
      c2sMac.update(decryptedPacket, 0, len + SSH_PACKET_LENGTH);
      byte[] blk = new byte[c2sMacSize];
      c2sMac.doFinal(blk, 0);

      int i = 0, j = len + SSH_PACKET_LENGTH;
      while (c2sMacSize-- > 0) {
        if (blk[i++] != packet[j++]) {
          throw new IOException(SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_MAC_ERROR));
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
