package io.github.grantchan.ssh.trans.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import java.io.IOException;

public interface KexHandler {

  void handleMessage(ChannelHandlerContext ctx, int cmd, ByteBuf req) throws IOException;

  void handleNewKeys(ChannelHandlerContext ctx, ByteBuf req);
}
