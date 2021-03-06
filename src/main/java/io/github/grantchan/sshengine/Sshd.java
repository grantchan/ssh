package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.server.transport.handler.ServerIdEx;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

import java.io.Closeable;

public class Sshd implements Closeable {

  private final EventLoopGroup boss = new NioEventLoopGroup(1);
  private final EventLoopGroup worker = new NioEventLoopGroup();

  public void open(int port) {
    ServerBootstrap b = new ServerBootstrap();
    LoggingHandler loggingHandler = new LoggingHandler(LogLevel.TRACE);

    try {
      b.group(boss, worker)
       .channel(NioServerSocketChannel.class)
       .handler(loggingHandler)
       .childHandler(new ChannelInitializer<SocketChannel>() {
         @Override
         protected void initChannel(SocketChannel ch) {
           ch.pipeline()
             .addLast(loggingHandler, new ServerIdEx());
         }
       }).bind(port).sync().channel().closeFuture().sync();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  @Override
  public void close() {
    boss.shutdownGracefully();
    worker.shutdownGracefully();
  }
}

