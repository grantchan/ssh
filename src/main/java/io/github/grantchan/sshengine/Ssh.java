package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.client.transport.handler.ClientReqHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

public class Ssh {

  public static void main(String[] args) {

    EventLoopGroup worker = new NioEventLoopGroup();

    Bootstrap bs = new Bootstrap();
    try {
      bs.group(worker)
        .channel(NioSocketChannel.class)
        .remoteAddress("127.0.0.1", 22)
        .handler(new ChannelInitializer<SocketChannel>() {
          @Override
          protected void initChannel(SocketChannel ch) {
            ch.pipeline().addLast(new LoggingHandler(LogLevel.TRACE),
                                  new ClientReqHandler("guest"));
          }
        }).connect().sync().channel().closeFuture().sync();
    } catch (InterruptedException e) {
      e.printStackTrace();
    } finally {
      worker.shutdownGracefully();
    }
  }
}
