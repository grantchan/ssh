package io.github.grantchan.ssh.client.handler;

import io.github.grantchan.ssh.common.Session;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class RequestHandler extends ChannelInboundHandlerAdapter {

  private Session session;

  public RequestHandler(Session session) {
    this.session = session;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    super.channelRead(ctx, msg);
  }
}
