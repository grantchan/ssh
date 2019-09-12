package io.github.grantchan.sshengine.common.transport.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

import java.util.concurrent.atomic.AtomicLong;

public abstract class AbstractPacketEncoder extends ChannelOutboundHandlerAdapter
                                            implements PacketEncoder {

  AtomicLong seq = new AtomicLong(0); // packet sequence number

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
    ByteBuf buf = encode((ByteBuf) msg, seq);

    ctx.write(buf, promise);
  }
}
