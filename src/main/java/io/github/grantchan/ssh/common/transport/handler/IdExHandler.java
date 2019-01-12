package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ByteProcessor;

import java.nio.charset.StandardCharsets;

public class IdExHandler extends ChannelInboundHandlerAdapter {

  /*
   * RFC 4253: The maximum length of the string is 255 characters,
   * including the Carriage Return and Line Feed.
   */
  private final int MAX_IDENTIFICATION_LINE_LENGTH = 255;

  protected Session session;
  protected ByteBuf accuBuf;

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    session = new Session(ctx);
    accuBuf = session.createBuffer();
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    accuBuf.writeBytes((ByteBuf) msg);
  }

  /*
   * Get the remote peer's identification
   * @return the identification if successful, otherwise null.
   */
  protected String getId() {
    int rIdx = accuBuf.readerIndex();
    int wIdx = accuBuf.writerIndex();
    if (rIdx == wIdx) {
      return null;
    }

    final String[] id = {null};

    ByteProcessor findId = new ByteProcessor() {
      private int line = 1, pos = 0;
      private boolean needLf = false;
      private boolean validLine = false;

      private byte[] data = new byte[MAX_IDENTIFICATION_LINE_LENGTH];

      @Override
      public boolean process(byte b) throws Exception {

        /* RFC 4253: The null character MUST NOT be sent. */
        if (b == '\0') {
          throw new IllegalStateException("Illegal identification - null character found at" +
              " line #" + line + " character #" + pos + 1);
        }

        if (b == '\r') {
          needLf = true;
          return true;
        }

        if (b == '\n') {
          line++;

          if (validLine) {
            id[0] = new String(data, 0, pos, StandardCharsets.UTF_8);
            return false;
          }
          pos = 0;
          needLf = false;
          return true;
        }

        if (needLf) {
          throw new IllegalStateException("Illegal identification - invalid line ending at" +
              " line #" + line + " character #" + pos + 1);
        }

        if (pos > data.length) {
          throw new IllegalStateException("Illegal identification - line too long at" +
              " line #" + line + " character #" + pos + 1);
        }

        if (pos < 4) {
          data[pos++] = b;
        } else if (data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-') {
          validLine = true;
          data[pos++] = b;
        }

        return true;
      }
    };

    int i = accuBuf.forEachByte(rIdx, wIdx - rIdx, findId);
    if (i == -1) {
      // packet is not fully received, restore reader index and return
      accuBuf.readerIndex(rIdx);
      return null;
    }

    accuBuf.readerIndex(i + 1);
    accuBuf.discardReadBytes();

    return id[0];
  }

}
