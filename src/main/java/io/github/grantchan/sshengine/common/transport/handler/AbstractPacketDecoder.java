package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public abstract class AbstractPacketDecoder extends ChannelInboundHandlerAdapter
                                            implements PacketDecoder {

  private ByteBuf accrued;

  private AtomicInteger step = new AtomicInteger(0);
  private AtomicLong seq = new AtomicLong(0); // packet sequence number

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    AbstractSession session = Objects.requireNonNull(getSession(), "Session is not initialized");
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
           (packet = decode(accrued, step, seq)) != null) {  // received packet should be bigger
                                                             // than a block
      ctx.fireChannelRead(packet);

      accrued.discardReadBytes();
    }
    ReferenceCountUtil.release(msg);
  }
}
