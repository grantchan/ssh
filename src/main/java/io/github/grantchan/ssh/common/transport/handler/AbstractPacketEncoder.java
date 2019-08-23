package io.github.grantchan.ssh.common.transport.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

public abstract class AbstractPacketEncoder extends ChannelOutboundHandlerAdapter
                                            implements PacketEncoder {

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
    ByteBuf buf = encode((ByteBuf) msg);

    ctx.write(buf, promise);
  }
}
