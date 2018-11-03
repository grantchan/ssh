package io.github.grantchan.ssh.trans.handler;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.cipher.BuiltinCipherFactory;
import io.github.grantchan.ssh.trans.compression.BuiltinCompressionFactory;
import io.github.grantchan.ssh.trans.kex.BuiltinKexHandlerFactory;
import io.github.grantchan.ssh.trans.kex.KexParam;
import io.github.grantchan.ssh.trans.mac.BuiltinMacFactory;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RequestHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session    session;
  private KexHandler kex;

  public RequestHandler(Session session) {
    this.session = session;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf req = (ByteBuf) msg;

    int cmd = req.readByte() & 0xFF;
    logger.info("Handling message - {} ...", SshMessage.from(cmd));

    switch (cmd) {
      case SshMessage.SSH_MSG_DISCONNECT:
        handleDisconnect(req);
        break;

      case SshMessage.SSH_MSG_IGNORE:
      case SshMessage.SSH_MSG_UNIMPLEMENTED:
      case SshMessage.SSH_MSG_DEBUG:
        // ignore
        break;

      case SshMessage.SSH_MSG_KEXINIT:
        handleKexInit(req);
        break;

      case SshMessage.SSH_MSG_SERVICE_REQUEST:
        handleServiceRequest(req);
        break;

      case SshMessage.SSH_MSG_NEWKEYS:
        handleNewKeys(req);
        break;

      default:
        if (cmd >= SshMessage.SSH_MSG_KEXDH_FIRST && cmd <= SshMessage.SSH_MSG_KEXDH_LAST) {
          kex.handleMessage(cmd, req);
        } else {
          Service svc = session.getService();
          if (svc != null) {
            svc.handleMessage(cmd, req);
          } else {
            throw new IllegalStateException("Unknown request command - " + SshMessage.from(cmd));
          }
        }
    }
  }

  private void handleDisconnect(ByteBuf req) {
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
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-11.1">Disconnection Message</a>
     */
    int code = req.readInt();
    String msg = SshIoUtil.readUtf8(req);

    session.handleDisconnect(code, msg);
  }

  protected void handleKexInit(ByteBuf msg) throws IOException {
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
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-7.1">Algorithm Negotiation</a>
     */
    int startPos = msg.readerIndex();
    msg.skipBytes(SshConstant.MSG_KEX_COOKIE_SIZE);

    List<String> kexInit = resolveKexInit(msg);
    session.setKexParams(kexInit);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    byte[] clientKexInit = new byte[payloadLen + 1];
    clientKexInit[0] = SshMessage.SSH_MSG_KEXINIT;
    msg.getBytes(startPos, clientKexInit, 1, payloadLen);
    session.setC2sKex(clientKexInit);

    kex = BuiltinKexHandlerFactory.create(kexInit.get(KexParam.KEX), session);
    if (kex == null) {
      throw new IOException("Unknown key exchange: " + KexParam.KEX);
    }
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    // factory
    String c2s = SshIoUtil.readUtf8(buf);
    String s2c = BuiltinKexHandlerFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.KEX, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.KEX));

    // server host key
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinSignatureFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.SERVER_HOST_KEY, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.SERVER_HOST_KEY));

    // encryption c2s
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinCipherFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.ENCRYPTION_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.ENCRYPTION_C2S));

    // encryption s2c
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinCipherFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.ENCRYPTION_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.ENCRYPTION_S2C));

    // mac c2s
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinMacFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.MAC_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.MAC_C2S));

    // mac s2c
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinMacFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.MAC_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.MAC_S2C));

    // compression c2s
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinCompressionFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.COMPRESSION_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.COMPRESSION_C2S));

    // compression s2c
    c2s = SshIoUtil.readUtf8(buf);
    s2c = BuiltinCompressionFactory.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.COMPRESSION_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.COMPRESSION_S2C));

    // language c2s
    c2s = SshIoUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexParam.LANGUAGE_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexParam.LANGUAGE_C2S));

    // language s2c
    c2s = SshIoUtil.readUtf8(buf);
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

  private void handleServiceRequest(ByteBuf req) {
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
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-10">Service Request</a>
     */
    String svcName = SshIoUtil.readUtf8(req);
    logger.info(svcName);

    try {
      session.acceptService(svcName);
    } catch (Exception e) {
      logger.info("Requested service ({}) from {} is unavailable, rejected.",
                  svcName, session.getRemoteAddress());

      // disconnect
      session.disconnect(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                         "Bad service requested - '" + svcName + "'");
      return;
    }
    session.replyAccept(svcName);

    // send welcome banner
  }

  private void handleNewKeys(ByteBuf req) {
    /*
     * RFC 4253:
     * The client sends SSH_MSG_NEWKEYS:
     *   byte      SSH_MSG_NEWKEYS
     *
     * Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.
     * This message is sent with the old keys and algorithms.  All messages
     * sent after this message MUST use the new keys and algorithms.
     *
     * When this message is received, the new keys and algorithms MUST be
     * used for receiving.
     *
     * The purpose of this message is to ensure that a party is able to
     * respond with an SSH_MSG_DISCONNECT message that the other party can
     * understand if something goes wrong with the key exchange.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-7.3">Taking Keys Into Use</a>
     */
    kex.handleNewKeys(req);
  }
}
