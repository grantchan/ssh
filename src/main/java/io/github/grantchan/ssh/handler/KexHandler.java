package io.github.grantchan.ssh.handler;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.kex.CipherFactory;
import io.github.grantchan.ssh.kex.MacFactory;
import io.github.grantchan.ssh.kex.SignatureFactory;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static io.github.grantchan.ssh.common.SshConstant.*;
import static io.github.grantchan.ssh.util.SshByteBufUtil.readUtf8;

public class KexHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private byte[] clientKexInit = null; // the payload of the client's SSH_MSG_KEXINIT

  private List<String> kexInit = null;
  private int min = -1, n, max = -1;

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf buf = (ByteBuf) msg;

    int cmd = buf.readByte() & 0xFF;
    switch (cmd) {
      case SSH_MSG_KEXINIT:
        /*
         * the client sends SSH_MSG_KEXINIT:
         * byte         SSH_MSG_KEXINIT
         * byte[16]     cookie (random bytes)
         * name-list    kex_algorithms
         * name-list    server_host_key_algorithms
         * name-list    encryption_algorithms_client_to_server
         * name-list    encryption_algorithms_server_to_client
         * name-list    mac_algorithms_client_to_server
         * name-list    mac_algorithms_server_to_client
         * name-list    compression_algorithms_client_to_server
         * name-list    compression_algorithms_server_to_client
         * name-list    languages_client_to_server
         * name-list    languages_server_to_client
         * boolean      first_kex_packet_follows
         * uint32       0 (reserved for future extension)
         */
        onMsgKexInit(ctx, buf);
        break;

      case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
        /*
         * the client sends SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
         * byte     SSH_MSG_KEX_DH_GEX_REQUEST_OLD
         * uint32   n, preferred size in bits of the group the server will send
         */
        n = buf.readInt();
        onMsgKexDhGexRequest(ctx, min, n, max);
        break;

      case SSH_MSG_KEX_DH_GEX_REQUEST:
        /*
         * the client sends SSH_MSG_KEX_DH_GEX_REQUEST:
         * byte     SSH_MSG_KEX_DH_GEX_REQUEST
         * uint32   min, minimal size in bits of an acceptable group
         * uint32   n,   preferred size in bits of the group the server will send
         * uint32   max, maximal size in bits of an acceptable group
         */
        min = buf.readInt();
        n = buf.readInt();
        max = buf.readInt();
        onMsgKexDhGexRequest(ctx, min, n, max);
        break;
    }
  }

  protected void onMsgKexInit(ChannelHandlerContext ctx, ByteBuf msg) {
    int startPos = msg.readerIndex();
    msg.skipBytes(MSG_KEX_COOKIE_SIZE);

    kexInit = resolveKexInit(msg);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    clientKexInit = new byte[payloadLen + 1];
    clientKexInit[0] = SSH_MSG_KEXINIT;
    msg.getBytes(startPos, clientKexInit, 1, payloadLen);
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    // kex
    String c2s = readUtf8(buf);
    String s2c = "diffie-hellman-group-exchange-sha1";
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(0, negotiate(c2s, s2c));

    // server host key
    c2s = readUtf8(buf);
    s2c = NamedObject.getNames(SignatureFactory.values);
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(1, negotiate(c2s, s2c));

    // encryption c2s
    c2s = readUtf8(buf);
    s2c = NamedObject.getNames(CipherFactory.values);
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(2, negotiate(c2s, s2c));

    // encryption s2c
    c2s = readUtf8(buf);
    s2c = NamedObject.getNames(CipherFactory.values);
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(3, negotiate(c2s, s2c));

    // mac c2s
    c2s = readUtf8(buf);
    s2c = NamedObject.getNames(MacFactory.values);
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(4, negotiate(c2s, s2c));

    // mac s2c
    c2s = readUtf8(buf);
    s2c = NamedObject.getNames(MacFactory.values);
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(5, negotiate(c2s, s2c));

    // compression c2s
    c2s = readUtf8(buf);
    s2c = "none";
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(6, negotiate(c2s, s2c));

    // compression s2c
    c2s = readUtf8(buf);
    s2c = "none";
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(7, negotiate(c2s, s2c));

    // language c2s
    c2s = readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(8, negotiate(c2s, s2c));

    // language s2c
    c2s = readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}\nclient said: {}", s2c, c2s);
    result.add(9, negotiate(c2s, s2c));

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

  protected void onMsgKexDhGexRequest(ChannelHandlerContext ctx, int min, int n, int max) {
    /*
     * the server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     * byte     SSH_MSG_KEX_DH_GEX_GROUP
     * mpint    p, safe prime
     * mpint    g, generator for subgroup in GF(p)
     */


  }
}
