package io.github.grantchan.ssh.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

import static io.github.grantchan.ssh.common.SshConstant.SSH_MSG_KEXINIT;
import static io.github.grantchan.ssh.common.SshConstant.SSH_PACKET_LENGTH;

public class KeyExchangeHandler extends ChannelInboundHandlerAdapter {

  private ByteBuf accuBuf;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
    accuBuf = ctx.alloc().buffer();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
    accuBuf.release();
    accuBuf = null;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accuBuf.writeBytes((ByteBuf) msg);

    while (accuBuf.readableBytes() > 0) {
      int wIdx = accuBuf.writerIndex();

      int pkLen = decode();
      if (pkLen != -1) {
        int cmd = accuBuf.readByte() & 0xFF;
        switch (cmd) {
          case SSH_MSG_KEXINIT:
            break;
        }

        accuBuf.writerIndex(wIdx); // restore the writer index
        accuBuf.readerIndex(pkLen + SSH_PACKET_LENGTH);
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
    byte[] packet = new byte[accuBuf.readableBytes()];
    accuBuf.getBytes(0, packet);

    int pkLen  = accuBuf.readInt();

    // if the packet has not been fully received, restore the reader pointer
    if (accuBuf.readableBytes() < pkLen) {
      accuBuf.readerIndex(0);
      return -1;
    }

    int pad = accuBuf.readByte() & 0xFF;
    accuBuf.writerIndex(pkLen + SSH_PACKET_LENGTH - pad);

    return pkLen;
  }
}
