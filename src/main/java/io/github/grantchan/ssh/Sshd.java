package io.github.grantchan.ssh;

import io.github.grantchan.ssh.trans.handler.IdexHandler;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

public class Sshd {

  public static void main(String[] args) {

    EventLoopGroup boss   = new NioEventLoopGroup(1);
    EventLoopGroup worker = new NioEventLoopGroup();

    ServerBootstrap b = new ServerBootstrap();
    LoggingHandler loggingHandler = new LoggingHandler(LogLevel.INFO);
    try {
      b.group(boss, worker)
       .channel(NioServerSocketChannel.class)
       .handler(loggingHandler)
       .childHandler(new ChannelInitializer<SocketChannel>() {
         @Override
         protected void initChannel(SocketChannel ch) throws Exception {
           ch.pipeline()
             .addLast(loggingHandler, new IdexHandler());
         }
       }).bind(5222).sync().channel().closeFuture().sync();
    } catch (InterruptedException e) {
      e.printStackTrace();
    } finally {
      boss.shutdownGracefully();
      worker.shutdownGracefully();
    }
  }
}

