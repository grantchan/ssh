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
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.github.grantchan.ssh.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class RequestHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  // The numbers 30-49 are key exchange specific and may be redefined by other kex methods.
  private static final byte SSH_MSG_KEXDH_FIRST = 30;
  private static final byte SSH_MSG_KEXDH_LAST  = 49;

  protected Session session;
  private KexHandler kexHandler;

  public RequestHandler() {
  }

  public RequestHandler(Session session) {
    this.session = Objects.requireNonNull(session);
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf req = (ByteBuf) msg;

    int cmd = req.readByte() & 0xFF;
    logger.info("[{}] Handling message - {} ...", session, SshMessage.from(cmd));

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

      case SshMessage.SSH_MSG_SERVICE_ACCEPT:
        handleServiceAccept(req);
        break;

      case SshMessage.SSH_MSG_NEWKEYS:
        handleNewKeys(req);
        break;

      default:
        if (cmd >= SSH_MSG_KEXDH_FIRST && cmd <= SSH_MSG_KEXDH_LAST) {
          kexHandler.handleMessage(cmd, req);
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

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
    logger.debug("[" + session + "] exceptionCaught details", t);

    if (t instanceof SshException) {
      int reasonCode = ((SshException) t).getDisconnectReason();
      if (reasonCode > 0) {
        session.disconnect(reasonCode, t.getMessage());
      }
    }
    ctx.channel().close();
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
    String msg = ByteBufIo.readUtf8(req);

    session.handleDisconnect(code, msg);
  }

  private void handleKexInit(ByteBuf msg) throws IOException {
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

  /**
   * Negotiate the key exchange method, public key algorithm, symmetric encryption algorithm,
   * message authentication algorithm, and hash algorithm supported by both parties.
   *
   * It iterates over client's kex algorithms, on at a time, choose the first algorithm that the
   * server also supports.
   *
   * @param c2s kex algorithms sent by client
   * @param s2c kex algorithms sent by server
   * @return the negotiated result, if failed, returns null
   */
  String negotiate(String c2s, String s2c) {
    String[] c = c2s.split(",");
    String[] s = s2c.split(",");

    for (String ci : c) {
      for (String si : s) {
        if (ci.equals(si)) {
          return ci;
        }
      }
    }
    return null;
  }

  protected void handleServiceRequest(ByteBuf req) throws SshException {
    throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
        "Unsupported message - SSH_MSG_SERVICE_REQUEST");
  }

  protected void handleServiceAccept(ByteBuf req) throws SshException {
    throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
        "Unsupported message - SSH_MSG_SERVICE_ACCEPT");
  }

  protected void handleNewKeys(ByteBuf req) throws SshException {
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
    byte[] id = session.getId();

    logger.debug("[{}] Session ID: {}", session, Bytes.md5(id));

    ByteBuf buf = session.createBuffer();

    KeyExchange kex = kexHandler.getKex();
    BigInteger k = kex.getSecretKey();
    ByteBufIo.writeMpInt(buf, k);
    buf.writeBytes(id);
    buf.writeByte((byte) 0x41);
    buf.writeBytes(id);

    int readableBytes = buf.readableBytes();
    byte[] array = new byte[readableBytes];
    buf.readBytes(array);

    int j = readableBytes - id.length - 1;

    MessageDigest md = kexHandler.getMd();

    md.update(array);
    byte[] iv_c2s = md.digest();

    array[j]++;
    md.update(array);
    byte[] iv_s2c = md.digest();

    array[j]++;
    md.update(array);
    byte[] e_c2s = md.digest();

    array[j]++;
    md.update(array);
    byte[] e_s2c = md.digest();

    array[j]++;
    md.update(array);
    byte[] mac_c2s = md.digest();

    array[j]++;
    md.update(array);
    byte[] mac_s2c = md.digest();

    List<String> kp = session.getKexInit();

    boolean isServer = session.isServer();

    // server to client cipher
    CipherFactories s2cCf;
    s2cCf = Objects.requireNonNull(CipherFactories.from(kp.get(KexInitParam.ENCRYPTION_S2C)));
    e_s2c = hashKey(e_s2c, s2cCf.getBlkSize(), k);
    Cipher s2cCip = Objects.requireNonNull(s2cCf.create(e_s2c, iv_s2c,
        isServer ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE));

    session.setS2cCipher(s2cCip);
    session.setS2cCipherSize(s2cCf.getIvSize());

    // client to server cipher
    CipherFactories c2sCf;
    c2sCf = Objects.requireNonNull(CipherFactories.from(kp.get(KexInitParam.ENCRYPTION_C2S)));
    e_c2s = hashKey(e_c2s, c2sCf.getBlkSize(), k);
    Cipher c2sCip = Objects.requireNonNull(c2sCf.create(e_c2s, iv_c2s,
        isServer ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE));

    session.setC2sCipher(c2sCip);
    session.setC2sCipherSize(c2sCf.getIvSize());

    logger.debug("[{}] Session Cipher(S2C): {}, Session Cipher(C2S): {}", session, s2cCf, c2sCf);

    // server to client MAC
    MacFactories s2cMf;
    s2cMf = Objects.requireNonNull(MacFactories.from(kp.get(KexInitParam.MAC_S2C)));
    Mac s2cMac = s2cMf.create(mac_s2c);
    if (s2cMac == null) {
      throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR,
          "Unsupported S2C MAC: " + kp.get(KexInitParam.MAC_S2C));
    }

    session.setS2cMac(s2cMac);
    session.setS2cMacSize(s2cMf.getBlkSize());
    session.setS2cDefMacSize(s2cMf.getDefBlkSize());

    // client to server MAC
    MacFactories c2sMf;
    c2sMf = Objects.requireNonNull(MacFactories.from(kp.get(KexInitParam.MAC_C2S)));
    Mac c2sMac = c2sMf.create(mac_c2s);
    if (c2sMac == null) {
      throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR,
          "Unsupported C2S MAC: " + kp.get(KexInitParam.MAC_C2S));
    }

    session.setC2sMac(c2sMac);
    session.setC2sMacSize(c2sMf.getBlkSize());
    session.setC2sDefMacSize(c2sMf.getDefBlkSize());

    logger.debug("[{}] Session MAC(S2C): {}, Sesson MAC(C2S): {}",session, s2cMf, c2sMf);
  }

  private byte[] hashKey(byte[] e, int blockSize, BigInteger k) {
    byte[] h = session.getId();
    MessageDigest md = kexHandler.getMd();

    for (ByteBuf b = Unpooled.buffer(); e.length < blockSize; b.clear()) {
      ByteBufIo.writeMpInt(b, k);
      b.writeBytes(h);
      b.writeBytes(e);
      byte[] a = new byte[b.readableBytes()];
      b.readBytes(a);
      md.update(a);

      byte[] foo = md.digest();
      byte[] bar = new byte[e.length + foo.length];
      System.arraycopy(e, 0, bar, 0, e.length);
      System.arraycopy(foo, 0, bar, e.length, foo.length);
      e = bar;
    }
    return e;
  }

}
