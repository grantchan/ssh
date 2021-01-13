package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.transport.handler.ClientReqHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.AttributeKey;

import java.util.concurrent.CompletableFuture;

public class Ssh {

  public static final AttributeKey<CompletableFuture<ClientSession>> SSH_CONNECT_FUTURE =
      AttributeKey.valueOf(Ssh.class.getName());

  private EventLoopGroup worker;
  private Bootstrap bs;

  public void start() {
    worker = new NioEventLoopGroup();

    bs = new Bootstrap();
    bs.group(worker)
        .channel(NioSocketChannel.class)
        .handler(new ChannelInitializer<SocketChannel>() {
          @Override
          protected void initChannel(SocketChannel ch) throws Exception {
            ch.pipeline()
              .addLast(new LoggingHandler(LogLevel.TRACE), new ClientReqHandler());
          }
        });
  }

  public CompletableFuture<ClientSession> connect(String host, int port) {
    CompletableFuture<ClientSession> connFuture = new CompletableFuture<>();

    ChannelFuture cf = bs.connect(host, port);

    Channel channel = cf.channel();
    channel.attr(SSH_CONNECT_FUTURE).set(connFuture);

    cf.addListener(f -> {
      Throwable e = f.cause();
      if (e != null) {
        connFuture.completeExceptionally(e);
      } else if (f.isCancelled()) {
        connFuture.cancel(true);
      }
    });

    return connFuture;
  }

  public void stop() {
    if (worker != null) {
      worker.shutdownGracefully();
    }
  }
}
