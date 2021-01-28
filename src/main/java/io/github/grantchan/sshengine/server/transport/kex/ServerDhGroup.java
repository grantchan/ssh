package io.github.grantchan.sshengine.server.transport.kex;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.kex.Kex;
import io.github.grantchan.sshengine.common.transport.kex.KexGroup;
import io.github.grantchan.sshengine.common.transport.kex.KexProposal;
import io.github.grantchan.sshengine.common.transport.signature.Signature;
import io.github.grantchan.sshengine.common.transport.signature.SignatureFactories;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.github.grantchan.sshengine.util.publickey.PublicKeyUtil;
import io.netty.buffer.ByteBuf;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static io.github.grantchan.sshengine.util.buffer.Bytes.md5;
import static io.github.grantchan.sshengine.util.buffer.Bytes.sha256;

public class ServerDhGroup extends AbstractLogger implements KexGroup {

  private final MessageDigest md;

  protected final Kex kex;
  protected final ServerSession session;

  public ServerDhGroup(MessageDigest md, Kex kex, ServerSession session) {
    this.md = md;
    this.kex = kex;
    this.session = session;
  }

  @Override
  public MessageDigest getMd() {
    return md;
  }

  @Override
  public Kex getKex() {
    return kex;
  }

  @Override
  public void handle(int cmd, ByteBuf req) throws SignatureException, SshException {
    logger.debug("[{}] Handling key exchange message - {} ...", session, SshMessage.from(cmd));

    if (cmd != SshMessage.SSH_MSG_KEXDH_INIT) {
      throw new SshException(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
          "Invalid key exchange message, expect: SSH_MSG_KEXDH_INIT, actual: " +
              SshMessage.from(cmd));
    }

    /*
     * RFC 4253:
     * First, the client sends the following:
     *   byte    SSH_MSG_KEXDH_INIT
     *   mpint   e
     */
    BigInteger e = ByteBufIo.readMpInt(req);
    kex.receivedPubKey(e);

    /*
     * RFC 4253:
     * The server then responds with the following:
     *   byte      SSH_MSG_KEXDH_REPLY
     *   string    server public host key and certificates (K_S)
     *   mpint     f
     *   string    signature of H
     *
     *  The hash H is computed as the HASH hash of the concatenation of the following:
     *
     *   string    V_C, the client's identification string (CR and LF excluded)
     *   string    V_S, the server's identification string (CR and LF excluded)
     *   string    I_C, the payload of the client's SSH_MSG_KEXINIT
     *   string    I_S, the payload of the server's SSH_MSG_KEXINIT
     *   string    K_S, the host key
     *   mpint     e, exchange value sent by the client
     *   mpint     f, exchange value sent by the server
     *   mpint     K, the shared secret
     *
     *  This value is called the exchange hash, and it is used to
     *  authenticate the key exchange.  The exchange hash SHOULD be kept
     *  secret.
     *
     *  The signature algorithm MUST be applied over H, not the original
     *  data.  Most signature algorithms include hashing and additional
     *  padding (e.g., "ssh-dss" specifies SHA-1 hashing).  In that case, the
     *  data is first hashed with HASH to compute H, and H is then hashed
     *  with SHA-1 as part of the signing operation.
     */
    String v_c = session.getClientId();
    String v_s = session.getServerId();
    byte[] i_c = session.getRawC2sKex();
    byte[] i_s = session.getRawS2cKex();

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("RSA");
    } catch (NoSuchAlgorithmException e1) {
      e1.printStackTrace();
      return;
    }
    KeyPair kp = kpg.generateKeyPair();

    RSAPublicKey pubKey = ((RSAPublicKey) kp.getPublic());

    byte[] k_s = PublicKeyUtil.bytesOf(pubKey);

    logger.debug("[{}] Host RSA public key fingerprint MD5: {}, SHA256: {}",
        session, md5(k_s), sha256(k_s));

    byte[] h_s = Bytes.concat(
        Bytes.joinWithLength(v_c, v_s),
        Bytes.joinWithLength(i_c, i_s, k_s),
        Bytes.joinWithLength(e, kex.getPubKey(), kex.getSecretKey())
    );

    md.update(h_s, 0, h_s.length);
    byte[] h = md.digest();
    session.setRawId(h);

    List<String> kexParams = session.getKexInit();

    Signature sig = SignatureFactories.create(kexParams.get(KexProposal.Param.SERVER_HOST_KEY),
        kp.getPrivate());
    if (sig == null) {
      throw new IllegalArgumentException("Unknown signature: " + KexProposal.Param.SERVER_HOST_KEY);
    }

    sig.update(h);

    byte[] sigH = Bytes.concat(
          Bytes.addLen(kexParams.get(KexProposal.Param.SERVER_HOST_KEY)),
          Bytes.addLen(sig.sign())
        );

    session.replyKexDhReply(k_s, kex.getPubKey(), sigH);
    logger.debug("[{}] KEX process completed after SSH_MSG_KEXDH_INIT", session);

    session.requestKexNewKeys();
  }
}
