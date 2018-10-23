package io.github.grantchan.ssh.trans.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import java.io.IOException;

public class DhKexHandler implements KexHandler {

  @Override
  public void handleMessage(ChannelHandlerContext ctx, int cmd, ByteBuf req) throws IOException {
  }

  @Override
  public void handleNewKeys(ChannelHandlerContext ctx, ByteBuf req) {
  }
}
