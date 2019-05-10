package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.common.transport.compression.CompressionFactories;
import io.github.grantchan.ssh.common.transport.kex.KexHandler;
import io.github.grantchan.ssh.common.transport.kex.KexHandlerFactories;
import io.github.grantchan.ssh.common.transport.kex.KexInitParam;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static io.github.grantchan.ssh.common.transport.handler.RequestHandler.negotiate;

public abstract class AbstractRequestHandler extends ChannelInboundHandlerAdapter
                                             implements RequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private KexHandler kexHandler;

  @Override
  public KexHandler getKexHandler() {
    return kexHandler;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");

    ByteBuf req = (ByteBuf) msg;
    int cmd = req.getByte(req.readerIndex()) & 0xFF;
    logger.info("[{}] Handling message - {} ...", session, SshMessage.from(cmd));

    handle(req);
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");

    logger.debug("[" + session + "] exceptionCaught details", t);

    if (t instanceof SshException) {
      int reasonCode = ((SshException) t).getDisconnectReason();
      if (reasonCode > 0) {
        session.disconnect(reasonCode, t.getMessage());
      }
    }
    ctx.channel().close();
  }

  public void handleDisconnect(ByteBuf req) {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");

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
    String msg = ByteBufIo.readUtf8(req);

    session.handleDisconnect(code, msg);
  }

  public void handleKexInit(ByteBuf msg) throws IOException {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");

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
    byte[] kiBytes = new byte[payloadLen + 1];
    kiBytes[0] = SshMessage.SSH_MSG_KEXINIT;
    msg.getBytes(startPos, kiBytes, 1, payloadLen);

    kexHandler = KexHandlerFactories.create(kexInit.get(KexInitParam.KEX), session);
    if (kexHandler == null) {
      throw new IOException("Unknown key exchange: " + KexInitParam.KEX);
    }

    if (session.isServer()) {
      session.setC2sKex(kiBytes);
    } else {
      session.setS2cKex(kiBytes);

      kexHandler.handleMessage(SshMessage.SSH_MSG_KEXDH_INIT, null);
    }
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    Session session = Objects.requireNonNull(getSession(), "Session is not initialized");

    List<String> result = new ArrayList<>(10);

    boolean isServer = session.isServer();

    // kex
    String they = ByteBufIo.readUtf8(buf);
    String we = KexHandlerFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String kex = isServer ? negotiate(they, we) : negotiate(we, they);
    if (kex == null) {
      throw new IllegalStateException("Failed to negotiate the KEX key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.KEX, kex);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.KEX));

    // server host key
    they = ByteBufIo.readUtf8(buf);
    we = SignatureFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String shk = isServer ? negotiate(they, we) : negotiate(we, they);
    if (shk == null) {
      throw new IllegalStateException("Failed to negotiate the Server Host Key key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.SERVER_HOST_KEY, shk);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.SERVER_HOST_KEY));

    // encryption c2s
    they = ByteBufIo.readUtf8(buf);
    we = CipherFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String encc2s = isServer ? negotiate(they, we) : negotiate(we, they);
    if (encc2s == null) {
      throw new IllegalStateException("Failed to negotiate the Encryption C2S key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.ENCRYPTION_C2S, encc2s);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.ENCRYPTION_C2S));

    // encryption s2c
    they = ByteBufIo.readUtf8(buf);
    we = CipherFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String encs2c = isServer ? negotiate(they, we) : negotiate(we, they);
    if (encs2c == null) {
      throw new IllegalStateException("Failed to negotiate the Encryption S2C key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.ENCRYPTION_S2C, encs2c);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.ENCRYPTION_S2C));

    // mac c2s
    they = ByteBufIo.readUtf8(buf);
    we = MacFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String macc2s = isServer ? negotiate(they, we) : negotiate(we, they);
    if (macc2s == null) {
      throw new IllegalStateException("Failed to negotiate the MAC C2S key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.MAC_C2S, macc2s);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.MAC_C2S));

    // mac s2c
    they = ByteBufIo.readUtf8(buf);
    we = MacFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String macs2c = isServer ? negotiate(they, we) : negotiate(we, they);
    if (macs2c == null) {
      throw new IllegalStateException("Failed to negotiate the MAC S2C key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.MAC_S2C, macs2c);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.MAC_S2C));

    // compression c2s
    they = ByteBufIo.readUtf8(buf);
    we = CompressionFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String compc2s = isServer ? negotiate(they, we) : negotiate(we, they);
    if (compc2s == null) {
      throw new IllegalStateException("Failed to negotiate the Compression C2S key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.COMPRESSION_C2S, compc2s);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.COMPRESSION_C2S));

    // compression s2c
    they = ByteBufIo.readUtf8(buf);
    we = CompressionFactories.getNames();
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    String comps2c = isServer ? negotiate(they, we) : negotiate(we, they);
    if (comps2c == null) {
      throw new IllegalStateException("Failed to negotiate the Compression S2C key exchange " +
          "parameter between client and server, our parameters: " + we + ", their parameters: " +
          they);
    }
    result.add(KexInitParam.COMPRESSION_S2C, comps2c);
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.COMPRESSION_S2C));

    // language c2s
    they = ByteBufIo.readUtf8(buf);
    we = "";
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    result.add(KexInitParam.LANGUAGE_C2S, isServer ? negotiate(they, we) : negotiate(we, they));
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.LANGUAGE_C2S));

    // language s2c
    they = ByteBufIo.readUtf8(buf);
    we = "";
    logger.debug("[{}] {}: {}", session, isServer ? "Server" : "Client", we);
    logger.debug("[{}] {}: {}", session, isServer ? "Client" : "Server", they);
    result.add(KexInitParam.LANGUAGE_S2C, isServer ? negotiate(they, we) : negotiate(we, they));
    logger.debug("[{}] negotiated: {}", session, result.get(KexInitParam.LANGUAGE_S2C));

    return result;
  }

  public void handleServiceRequest(ByteBuf req) throws SshException {
  }

  public void handleServiceAccept(ByteBuf req) throws SshException {
  }

  public void handleNewKeys(ByteBuf req) throws SshException {
  }
}
