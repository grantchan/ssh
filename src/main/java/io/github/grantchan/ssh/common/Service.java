package io.github.grantchan.ssh.common;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

public interface Service {

  void handleMessage(ChannelHandlerContext ctx, int cmd, ByteBuf req);
}
