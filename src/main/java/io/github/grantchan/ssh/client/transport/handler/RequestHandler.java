package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.common.transport.handler.AbstractRequestHandler;
import io.github.grantchan.ssh.common.transport.handler.IdExHandler;
import io.github.grantchan.ssh.common.transport.kex.KexHandler;
import io.github.grantchan.ssh.common.transport.kex.KexInitProposal;
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.github.grantchan.ssh.util.buffer.Bytes;
import io.github.grantchan.ssh.util.buffer.LengthBytesBuilder;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static io.github.grantchan.ssh.common.transport.handler.RequestHandler.hashKey;
import static io.github.grantchan.ssh.common.transport.handler.RequestHandler.negotiate;

public class RequestHandler extends AbstractRequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private ClientSession session;

  private ByteBuf accuBuf;
  private String username;

  public RequestHandler(String username) {
    this.username = username;
  }

  @Override
  public Session getSession() {
    return session;
  }

  @Override
  public void handlerAdded(ChannelHandlerContext ctx) {
    session = new ClientSession(ctx);

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
    session.setClientId("SSH-2.0-Client DEMO");
    session.setUsername(username);

    accuBuf = session.createBuffer();
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    String id = session.getServerId();
    if (id != null) {
      super.channelRead(ctx, msg);
      return;
    }

    accuBuf.writeBytes((ByteBuf) msg);

    id = IdExHandler.getId(accuBuf);
    if (id == null) {
      return;
    }
    session.setServerId(id);

    logger.debug("[{}] Received identification: {}", session, id);

    ctx.writeAndFlush(Unpooled.wrappedBuffer((session.getClientId() + "\r\n")
                                                     .getBytes(StandardCharsets.UTF_8)));

    ctx.pipeline().addFirst(new PacketDecoder(session));
    ctx.pipeline().addLast(new PacketEncoder(session));

    byte[] ki = IdExHandler.kexInit();
    session.setC2sKex(Bytes.concat(new byte[] {SshMessage.SSH_MSG_KEXINIT}, ki));

    session.sendKexInit(ki);

    ReferenceCountUtil.release(msg);
  }

  @Override
  protected List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    KexInitProposal.ALL.forEach(p -> {
      String they = ByteBufIo.readUtf8(buf);
      String we = Objects.requireNonNull(p).getProposals().get();
      logger.debug("[{}] {}(Client): {}", session, p.getName(), we);
      logger.debug("[{}] {}(Server): {}", session, p.getName(), they);

      String val = negotiate(we, they);
      if (val == null) {
        throw new IllegalStateException("Failed to negotiate the " + p.name() + "in key exchange. "
            + "- our proposals: " + we + ", their proposals: " + they);
      }
      result.add(p.getId(), val);
      logger.debug("[{}] negotiated: {}", session, val);
    });

    return result;
  }

  @Override
  public void setKexInit(byte[] ki) {
    session.setS2cKex(ki);
  }

  @Override
  public void handleKexInit(ByteBuf msg) throws IOException {
    super.handleKexInit(msg);

    getKexHandler().handleMessage(SshMessage.SSH_MSG_KEXDH_INIT, null);
  }

  @Override
  public void handleServiceAccept(ByteBuf req) throws SshException {
    super.handleServiceAccept(req);

    String service = ByteBufIo.readUtf8(req);

    logger.debug("[{}] Service accepted: {}", session, service);

    session.acceptService(service);

    /*
     * The "none" Authentication Request
     *
     * A client may request a list of authentication 'method name' values
     * that may continue by using the "none" authentication 'method name'.
     *
     * If no authentication is needed for the user, the server MUST return
     * SSH_MSG_USERAUTH_SUCCESS.  Otherwise, the server MUST return
     * SSH_MSG_USERAUTH_FAILURE and MAY return with it a list of methods
     * that may continue in its 'authentications that can continue' value.
     *
     * This 'method name' MUST NOT be listed as supported by the server.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.2">The "none" Authentication Request</a>
     */
    session.requestUserAuthRequest(session.getUsername(), "ssh-connection", "none");
  }

  @Override
  public void handleNewKeys(ByteBuf req) throws SshException {
    super.handleNewKeys(req);

    KexHandler kexHandler = Objects.requireNonNull(getKexHandler(), "Kex handler is not initalized");

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

    KeyExchange kex = kexHandler.getKex();
    BigInteger k = kex.getSecretKey();

    byte[] buf = Bytes.concat(
        LengthBytesBuilder.concat(k),
        id,
        new byte[]{(byte) 0x41},
        id
    );

    int j = buf.length - id.length - 1;

    MessageDigest md = kexHandler.getMd();

    md.update(buf);
    byte[] iv_c2s = md.digest();

    buf[j]++;
    md.update(buf);
    byte[] iv_s2c = md.digest();

    buf[j]++;
    md.update(buf);
    byte[] e_c2s = md.digest();

    buf[j]++;
    md.update(buf);
    byte[] e_s2c = md.digest();

    buf[j]++;
    md.update(buf);
    byte[] mac_c2s = md.digest();

    buf[j]++;
    md.update(buf);
    byte[] mac_s2c = md.digest();

    List<String> kp = session.getKexInit();

    // server to client cipher
    CipherFactories s2cCf;
    s2cCf = Objects.requireNonNull(CipherFactories.from(kp.get(KexInitProposal.Param.ENCRYPTION_S2C)));
    e_s2c = hashKey(e_s2c, s2cCf.getBlkSize(), k, id, md);
    Cipher s2cCip = Objects.requireNonNull(s2cCf.create(e_s2c, iv_s2c, Cipher.DECRYPT_MODE)
    );

    session.setS2cCipher(s2cCip);
    session.setS2cCipherSize(s2cCf.getIvSize());

    // client to server cipher
    CipherFactories c2sCf;
    c2sCf = Objects.requireNonNull(CipherFactories.from(kp.get(KexInitProposal.Param.ENCRYPTION_C2S)));
    e_c2s = hashKey(e_c2s, c2sCf.getBlkSize(), k, id, md);
    Cipher c2sCip = Objects.requireNonNull(c2sCf.create(e_c2s, iv_c2s, Cipher.ENCRYPT_MODE)
    );

    session.setC2sCipher(c2sCip);
    session.setC2sCipherSize(c2sCf.getIvSize());

    logger.debug("[{}] Session Cipher(S2C): {}, Session Cipher(C2S): {}", session, s2cCf, c2sCf);

    // server to client MAC
    MacFactories s2cMf;
    s2cMf = Objects.requireNonNull(MacFactories.from(kp.get(KexInitProposal.Param.MAC_S2C)));
    Mac s2cMac = s2cMf.create(mac_s2c);
    if (s2cMac == null) {
      throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR,
          "Unsupported S2C MAC: " + kp.get(KexInitProposal.Param.MAC_S2C));
    }

    session.setS2cMac(s2cMac);
    session.setS2cMacSize(s2cMf.getBlkSize());
    session.setS2cDefMacSize(s2cMf.getDefBlkSize());

    // client to server MAC
    MacFactories c2sMf;
    c2sMf = Objects.requireNonNull(MacFactories.from(kp.get(KexInitProposal.Param.MAC_C2S)));
    Mac c2sMac = c2sMf.create(mac_c2s);
    if (c2sMac == null) {
      throw new SshException(SshMessage.SSH_DISCONNECT_MAC_ERROR,
          "Unsupported C2S MAC: " + kp.get(KexInitProposal.Param.MAC_C2S));
    }

    session.setC2sMac(c2sMac);
    session.setC2sMacSize(c2sMf.getBlkSize());
    session.setC2sDefMacSize(c2sMf.getDefBlkSize());

    logger.debug("[{}] Session MAC(S2C): {}, Sesson MAC(C2S): {}",session, s2cMf, c2sMf);

    session.requestServiceRequest();
  }
}