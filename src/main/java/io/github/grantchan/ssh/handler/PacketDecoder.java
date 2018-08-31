package io.github.grantchan.ssh.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.github.grantchan.ssh.common.SshConstant.SSH_PACKET_LENGTH;

public class PacketDecoder extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected ByteBuf accuBuf;

  private int c2sCipBlkSize = 8, s2cCipBlkSize = 8;
  private int c2sMacBlkSize = 0, s2cMacBlkSize = 0;

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

    while (accuBuf.readableBytes() > c2sCipBlkSize) {
      int wIdx = accuBuf.writerIndex();

      int pkLen = decode();
      if (pkLen != -1) {
        ctx.fireChannelRead(accuBuf);

        // restore the writer index
        accuBuf.writerIndex(wIdx);

        // update reader index to the start of next packet
        accuBuf.readerIndex(pkLen + SSH_PACKET_LENGTH + c2sMacBlkSize);

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
  private int decode() {
    int rIdx = accuBuf.readerIndex();

    int pkLen  = accuBuf.readInt();

    if (accuBuf.readableBytes() < pkLen + c2sMacBlkSize) {
      // packet has not been fully received, restore the reader pointer
      accuBuf.readerIndex(rIdx);
      return -1;
    }

    int pad = accuBuf.readByte() & 0xFF;
    accuBuf.writerIndex(pkLen + SSH_PACKET_LENGTH - pad);

    return pkLen;
  }
}
