package io.github.grantchan.SshEngine.common.transport.handler;

import io.github.grantchan.SshEngine.common.Session;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

import java.util.Objects;

public abstract class AbstractPacketDecoder extends ChannelInboundHandlerAdapter
                                            implements PacketDecoder {

  private ByteBuf accrued;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");
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

    int blkSize = getBlkSize();

    ByteBuf packet;
    while (accrued.readableBytes() > blkSize &&
           (packet = decode(accrued)) != null) {  // received packet should be bigger
                                                  // than a block
      ctx.fireChannelRead(packet);

      accrued.discardReadBytes();
    }
    ReferenceCountUtil.release(msg);
  }
}
