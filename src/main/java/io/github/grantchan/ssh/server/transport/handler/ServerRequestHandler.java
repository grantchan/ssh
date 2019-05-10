package io.github.grantchan.ssh.server.transport.handler;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.common.transport.handler.AbstractRequestHandler;
import io.github.grantchan.ssh.common.transport.kex.KexHandler;
import io.github.grantchan.ssh.common.transport.kex.KexInitParam;
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.server.ServerSession;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.github.grantchan.ssh.util.buffer.Bytes;
import io.github.grantchan.ssh.util.buffer.LengthBytesBuilder;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;
import java.util.Objects;

import static io.github.grantchan.ssh.common.transport.handler.RequestHandler.hashKey;

public class ServerRequestHandler extends AbstractRequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private ServerSession session;

  ServerRequestHandler(ServerSession session) {
    this.session = session;
  }

  @Override
  public Session getSession() {
    return session;
  }

  @Override
  public void handleServiceRequest(ByteBuf req) throws SshException {
    super.handleServiceRequest(req);

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
    String svcName = ByteBufIo.readUtf8(req);
    logger.info(svcName);

    session.acceptService(svcName);

    session.replyAccept(svcName);

    // send welcome banner
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
    byte[] buf = Bytes.concat(LengthBytesBuilder.concat(k), id, new byte[]{(byte) 0x41}, id);

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
    s2cCf = Objects.requireNonNull(CipherFactories.from(kp.get(KexInitParam.ENCRYPTION_S2C)));
    e_s2c = hashKey(e_s2c, s2cCf.getBlkSize(), k, id, md);
    Cipher s2cCip = Objects.requireNonNull(s2cCf.create(e_s2c, iv_s2c, Cipher.ENCRYPT_MODE)
    );

    session.setS2cCipher(s2cCip);
    session.setS2cCipherSize(s2cCf.getIvSize());

    // client to server cipher
    CipherFactories c2sCf;
    c2sCf = Objects.requireNonNull(CipherFactories.from(kp.get(KexInitParam.ENCRYPTION_C2S)));
    e_c2s = hashKey(e_c2s, c2sCf.getBlkSize(), k, id, md);
    Cipher c2sCip = Objects.requireNonNull(c2sCf.create(e_c2s, iv_c2s, Cipher.DECRYPT_MODE)
    );

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
}