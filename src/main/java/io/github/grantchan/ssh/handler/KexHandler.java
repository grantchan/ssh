package io.github.grantchan.ssh.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static io.github.grantchan.ssh.common.SshConstant.*;
import static io.github.grantchan.ssh.util.SshByteBufUtil.readUtf8;

public class KexHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private byte[] clientKexInit = null; // the payload of the client's SSH_MSG_KEXINIT

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf buf = (ByteBuf) msg;

    int cmd = buf.readByte() & 0xFF;
    switch (cmd) {
      case SSH_MSG_KEXINIT:
        int startPos = buf.readerIndex();
        buf.skipBytes(MSG_KEX_COOKIE_SIZE);

        resolveKexInit(buf);

        buf.readBoolean();
        buf.readInt();

        int payloadLen = buf.readerIndex() - startPos;
        clientKexInit = new byte[payloadLen + 1];
        clientKexInit[0] = SSH_MSG_KEXINIT;
        buf.getBytes(startPos, clientKexInit, 1, payloadLen);

        break;
    }
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    String kex = readUtf8(buf);
    logger.info(kex);

    String serverHostKey = readUtf8(buf);
    logger.info(serverHostKey);

    String c2sEncryption = readUtf8(buf);
    logger.info(c2sEncryption);

    String s2cEncryption = readUtf8(buf);
    logger.info(s2cEncryption);

    String c2sMac = readUtf8(buf);
    logger.info(c2sMac);

    String s2cMac = readUtf8(buf);
    logger.info(s2cMac);

    String c2sCompression = readUtf8(buf);
    logger.info(c2sCompression);

    String s2cCompression = readUtf8(buf);
    logger.info(s2cCompression);

    String c2sLanguage = readUtf8(buf);
    logger.info(c2sLanguage);

    String s2cLanguage = readUtf8(buf);
    logger.info(s2cLanguage);

    return null;
  }
}
