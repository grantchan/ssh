package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.common.transport.compression.CompressionFactories;
import io.github.grantchan.ssh.common.transport.kex.KexHandlerFactories;
import io.github.grantchan.ssh.common.transport.kex.KexInitParam;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.github.grantchan.ssh.server.transport.kex.KexHandler;
import io.github.grantchan.ssh.util.buffer.SshByteBuf;
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

  // The numbers 30-49 are key exchange specific and may be redefined by other kex methods.
  private final byte SSH_MSG_KEXDH_FIRST = 30;
  private final byte SSH_MSG_KEXDH_LAST  = 49;

  protected Session session;
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
        if (cmd >= SSH_MSG_KEXDH_FIRST && cmd <= SSH_MSG_KEXDH_LAST) {
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
    String msg = SshByteBuf.readUtf8(req);

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
    session.setKexInit(kexInit);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    byte[] clientKexInit = new byte[payloadLen + 1];
    clientKexInit[0] = SshMessage.SSH_MSG_KEXINIT;
    msg.getBytes(startPos, clientKexInit, 1, payloadLen);
    session.setC2sKex(clientKexInit);

    kex = KexHandlerFactories.create(kexInit.get(KexInitParam.KEX), session);
    if (kex == null) {
      throw new IOException("Unknown key exchange: " + KexInitParam.KEX);
    }
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    // factory
    String c2s = SshByteBuf.readUtf8(buf);
    String s2c = KexHandlerFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.KEX, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.KEX));

    // server host key
    c2s = SshByteBuf.readUtf8(buf);
    s2c = SignatureFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.SERVER_HOST_KEY, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.SERVER_HOST_KEY));

    // encryption c2s
    c2s = SshByteBuf.readUtf8(buf);
    s2c = CipherFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.ENCRYPTION_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.ENCRYPTION_C2S));

    // encryption s2c
    c2s = SshByteBuf.readUtf8(buf);
    s2c = CipherFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.ENCRYPTION_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.ENCRYPTION_S2C));

    // mac c2s
    c2s = SshByteBuf.readUtf8(buf);
    s2c = MacFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.MAC_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.MAC_C2S));

    // mac s2c
    c2s = SshByteBuf.readUtf8(buf);
    s2c = MacFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.MAC_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.MAC_S2C));

    // compression c2s
    c2s = SshByteBuf.readUtf8(buf);
    s2c = CompressionFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.COMPRESSION_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.COMPRESSION_C2S));

    // compression s2c
    c2s = SshByteBuf.readUtf8(buf);
    s2c = CompressionFactories.getNames();
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.COMPRESSION_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.COMPRESSION_S2C));

    // language c2s
    c2s = SshByteBuf.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.LANGUAGE_C2S, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.LANGUAGE_C2S));

    // language s2c
    c2s = SshByteBuf.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(KexInitParam.LANGUAGE_S2C, negotiate(c2s, s2c));
    logger.debug("negotiated: {}", result.get(KexInitParam.LANGUAGE_S2C));

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

  protected void handleServiceRequest(ByteBuf req) {

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
