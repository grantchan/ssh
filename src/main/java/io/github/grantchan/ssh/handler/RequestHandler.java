package io.github.grantchan.ssh.handler;

import io.github.grantchan.ssh.common.*;
import io.github.grantchan.ssh.factory.*;
import io.github.grantchan.ssh.kex.KexParam;
import io.github.grantchan.ssh.util.SshByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class RequestHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session    session;
  private KexHandler kex;
  private Service    svc;

  public RequestHandler(Session session) {
    this.session = session;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf req = (ByteBuf) msg;

    int cmd = req.readByte() & 0xFF;
    logger.info("Handling message - {} ...", SshConstant.messageName(cmd));

    switch (cmd) {
      case SshConstant.SSH_MSG_DISCONNECT:
        handleDisconnect(ctx, req);
        break;

      case SshConstant.SSH_MSG_KEXINIT:
        handleKexInit(ctx, req);
        break;

      case SshConstant.SSH_MSG_SERVICE_REQUEST:
        handleServiceRequest(ctx, req);
        break;

      default:
        if (cmd >= SshConstant.SSH_MSG_NEWKEYS && cmd <= 49) {
          kex.handleMessage(ctx, cmd, req);
        } else if (cmd >= SshConstant.SSH_MSG_GLOBAL_REQUEST &&
                   cmd <= SshConstant.SSH_MSG_CHANNEL_FAILURE) {
          svc.handleMessage(cmd, req);
        } else {
          throw new IllegalStateException("Unknown request command - " + SshConstant.messageName(cmd));
        }
    }
  }

  private void handleDisconnect(ChannelHandlerContext ctx, ByteBuf req) {
    /*
     * RFC 4253:
     * The client sends SSH_MSG_DISCONNECT:
     *   byte      SSH_MSG_DISCONNECT
     *   uint32    reason code
     *   string    description in ISO-10646 UTF-8 encoding [RFC3629]
     *   string    language tag [RFC3066]
     *
     * This message causes immediate termination of the connection.  All
     * implementations MUST be able to process this message; they SHOULD be
     * able to send this message.
     *
     * The sender MUST NOT send or receive any data after this message, and
     * the recipient MUST NOT accept any data after receiving this message.
     * The Disconnection Message 'description' string gives a more specific
     * explanation in a human-readable form.  The Disconnection Message
     * 'reason code' gives the reason in a more machine-readable format
     * (suitable for localization)
     */
    int code = req.readInt();
    String msg = SshByteBufUtil.readUtf8(req);

    logger.info("Disconnecting... reason: {}, msg: {}", SshConstant.disconnectReason(code), msg);

    ctx.channel().close();
  }

  protected void handleKexInit(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * RFC 4253:
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
    msg.skipBytes(SshConstant.MSG_KEX_COOKIE_SIZE);

    List<String> kexInit = resolveKexInit(msg);
    session.setKexParams(kexInit);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    byte[] clientKexInit = new byte[payloadLen + 1];
    clientKexInit[0] = SshConstant.SSH_MSG_KEXINIT;
    msg.getBytes(startPos, clientKexInit, 1, payloadLen);
    session.setC2sKex(clientKexInit);

    try {
      kex = NamedFactory.create(KexFactory.values, kexInit.get(KexParam.KEX));
    } catch (Exception e) {
      e.printStackTrace();
    }
    assert kex != null;
    kex.setSession(session);
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    // factory
    String c2s = SshByteBufUtil.readUtf8(buf);
    String s2c = KexFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.KEX, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.KEX));

    // server host key
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = SignatureFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.SERVER_HOST_KEY, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.SERVER_HOST_KEY));

    // encryption c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = CipherFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.ENCRYPTION_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.ENCRYPTION_C2S));

    // encryption s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = CipherFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.ENCRYPTION_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.ENCRYPTION_S2C));

    // mac c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = MacFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.MAC_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.MAC_C2S));

    // mac s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = MacFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.MAC_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.MAC_S2C));

    // compression c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = CompressionFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.COMPRESSION_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.COMPRESSION_C2S));

    // compression s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = CompressionFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.COMPRESSION_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.COMPRESSION_S2C));

    // language c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.LANGUAGE_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.LANGUAGE_C2S));

    // language s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.LANGUAGE_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.LANGUAGE_S2C));

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

  private void handleServiceRequest(ChannelHandlerContext ctx, ByteBuf req) {
    /*
     * RFC 4253:
     * The client sends SSH_MSG_SERVICE_REQUEST:
     *   byte      SSH_MSG_SERVICE_REQUEST
     *   string    service name
     *
     * After the key exchange, the client requests a service.  The service
     * is identified by a name.  The format of names and procedures for
     * defining new names are defined in [SSH-ARCH] and [SSH-NUMBERS].
     *
     * Currently, the following names have been reserved:
     *
     *    ssh-userauth
     *    ssh-connection
     *
     * Similar local naming policy is applied to the service names, as is
     * applied to the algorithm names.  A local service should use the
     * PRIVATE USE syntax of "servicename@domain".
     *
     * If the server rejects the service request, it SHOULD send an
     * appropriate SSH_MSG_DISCONNECT message and MUST disconnect.
     *
     * When the service starts, it may have access to the session identifier
     * generated during the key exchange.
     */
    String svcName = SshByteBufUtil.readUtf8(req);
    logger.info(svcName);

    try {
      svc = NamedFactory.create(ServiceFactory.values, svcName);
    } catch (Exception e) {
      e.printStackTrace();
    }

    ByteBuf buf = ctx.alloc().buffer();
    buf.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    buf.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    buf.writeByte(SshConstant.SSH_MSG_SERVICE_ACCEPT);

    SshByteBufUtil.writeUtf8(buf, svcName);

    ctx.channel().writeAndFlush(buf);
  }
}
