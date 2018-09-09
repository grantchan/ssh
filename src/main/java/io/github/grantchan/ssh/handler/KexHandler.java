package io.github.grantchan.ssh.handler;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.kex.*;
import io.github.grantchan.ssh.util.SshByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static io.github.grantchan.ssh.common.SshConstant.*;

public class KexHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;
  private Kex     kex;

  public KexHandler(Session session) {
    this.session = session;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf req = (ByteBuf) msg;

    int cmd = req.readByte() & 0xFF;
    logger.debug("Handling message - {} ...", cmd);
    switch (cmd) {
      case SSH_MSG_KEXINIT:
        handleKexInit(ctx, req);
        break;

      default:
        if (cmd >= 30 && cmd <= 49) {
          kex.handleKexMessage(ctx, cmd, req);
        } else {
          throw new IllegalStateException("Unknown request command - " + cmd);
        }
    }
  }

  protected void handleKexInit(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * The client sends SSH_MSG_KEXINIT:
     *   byte         SSH_MSG_KEXINIT
     *   byte[16]     cookie (random bytes)
     *   name-list    kex_algorithms
     *   name-list    server_host_key_algorithms
     *   name-list    encryption_algorithms_client_to_server
     *   name-list    encryption_algorithms_server_to_client
     *   name-list    mac_algorithms_client_to_server
     *   name-list    mac_algorithms_server_to_client
     *   name-list    compression_algorithms_client_to_server
     *   name-list    compression_algorithms_server_to_client
     *   name-list    languages_client_to_server
     *   name-list    languages_server_to_client
     *   boolean      first_kex_packet_follows
     *   uint32       0 (reserved for future extension)
     */
    int startPos = msg.readerIndex();
    msg.skipBytes(MSG_KEX_COOKIE_SIZE);

    List<String> kexInit = resolveKexInit(msg);
    session.setKexInitResult(kexInit);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    byte[] clientKexInit = new byte[payloadLen + 1];
    clientKexInit[0] = SSH_MSG_KEXINIT;
    msg.getBytes(startPos, clientKexInit, 1, payloadLen);
    session.setClientKexInit(clientKexInit);

    try {
      kex = Factory.create(KexFactory.values, kexInit.get(KexAlgorithm.KEX));
    } catch (Exception e) {
      e.printStackTrace();
    }
    assert kex != null;
    kex.setSession(session);
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    // kex
    String c2s = SshByteBufUtil.readUtf8(buf);
    String s2c = NamedObject.getNames(KexFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.KEX, negotiate(c2s, s2c));

    // server host key
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(SignatureFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.SERVER_HOST_KEY, negotiate(c2s, s2c));

    // encryption c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(CipherFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.ENCRYPTION_C2S, negotiate(c2s, s2c));

    // encryption s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(CipherFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.ENCRYPTION_S2C, negotiate(c2s, s2c));

    // mac c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(MacFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.MAC_C2S, negotiate(c2s, s2c));

    // mac s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(MacFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.MAC_S2C, negotiate(c2s, s2c));

    // compression c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "none";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.COMPRESSION_C2S, negotiate(c2s, s2c));

    // compression s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "none";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.COMPRESSION_S2C, negotiate(c2s, s2c));

    // language c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.LANGUAGE_C2S, negotiate(c2s, s2c));

    // language s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexAlgorithm.LANGUAGE_S2C, negotiate(c2s, s2c));

    return result;
  }

  private String negotiate(String c2s, String s2c) {
    String[] c = c2s.split(",");
    for (String ci : c) {
      if (s2c.contains(ci)) {
        return ci;
      }
    }
    return null;
  }
}
