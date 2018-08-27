package io.github.grantchan.ssh;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.ByteProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public class Sshd {

  private static Logger logger = LoggerFactory.getLogger(Sshd.class);

  public static void main(String[] args) {

    EventLoopGroup boss   = new NioEventLoopGroup(1);
    EventLoopGroup worker = new NioEventLoopGroup();

    ServerBootstrap b = new ServerBootstrap();
    try {
      b.group(boss, worker)
       .channel(NioServerSocketChannel.class)
       .handler(new LoggingHandler(LogLevel.INFO))
       .childHandler(new ChannelInitializer<SocketChannel>() {
         @Override
         protected void initChannel(SocketChannel ch) throws Exception {
           ch.pipeline()
             .addLast(new LoggingHandler(LogLevel.INFO),
                 new ChannelInboundHandlerAdapter() {
                   private String clientVer = null;

                   /*
                    * RFC 4253:
                    * Both the 'protoversion' and 'softwareversion' strings MUST consist of
                    * printable US-ASCII characters, with the exception of whitespace
                    * characters and the minus sign (-).
                    */
                   private final String serverVer = "SSH-2.0-DEMO";

                   private ByteBuf accuBuf;

                   @Override
                   public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
                     accuBuf = ctx.alloc().buffer();
                   }

                   @Override
                   public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
                     accuBuf.release();
                     accuBuf = null;
                   }

                   @Override
                   public void channelActive(ChannelHandlerContext ctx) throws Exception {
                     /*
                      * RFC 4253:
                      * When the connection has been established, both sides MUST send an
                      * identification string.  This identification string MUST be
                      *
                      *   SSH-protoversion-softwareversion SP comments CR LF
                      *
                      * Since the protocol being defined in this set of documents is version
                      * 2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
                      * OPTIONAL.  If the 'comments' string is included, a 'space' character
                      * (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
                      * and 'comments' strings.  The identification MUST be terminated by a
                      * single Carriage Return (CR) and a single Line Feed (LF) character
                      * (ASCII 13 and 10, respectively).
                      *
                      * ...
                      *
                      * The part of the identification string preceding the Carriage Return
                      * and Line Feed is used in the Diffie-Hellman key exchange.
                      *
                      * ...
                      *
                      * Key exchange will begin immediately after sending this identifier.
                      */
                     ctx.writeAndFlush(Unpooled.wrappedBuffer((serverVer + "\r\n").getBytes(StandardCharsets.UTF_8)));
                   }

                   @Override
                   public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                     accuBuf.writeBytes((ByteBuf) msg);

                     if (clientVer == null) {
                       clientVer = getId(accuBuf);
                       if (clientVer == null) {
                         return;
                       }
                       logger.info(clientVer);
                     }
                   }

                   /*
                    * Get the remote peer's identification
                    * @return the identification if successful, otherwise null.
                    */
                   private String getId(final ByteBuf buf) {
                     int rIdx = buf.readerIndex();
                     int wIdx = buf.writerIndex();
                     if (wIdx - rIdx <= 0) {
                       return null;
                     }

                     int i = buf.forEachByte(rIdx, wIdx - rIdx, ByteProcessor.FIND_LF);
                     if (i < 0) {
                       return null;
                     }

                     int len = i - rIdx + 1;
                     byte[] arr = new byte[len];
                     buf.readBytes(arr);

                     len--;
                     if (arr[len - 1] == '\r') {
                       len--;
                     }

                     buf.discardReadBytes();

                     return new String(arr, 0, len, StandardCharsets.UTF_8);
                   }
                 });
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

