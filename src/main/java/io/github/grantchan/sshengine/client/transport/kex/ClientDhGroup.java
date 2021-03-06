package io.github.grantchan.sshengine.client.transport.kex;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.kex.Kex;
import io.github.grantchan.sshengine.common.transport.kex.KexGroup;
import io.github.grantchan.sshengine.common.transport.kex.KexProposal;
import io.github.grantchan.sshengine.common.transport.signature.Signature;
import io.github.grantchan.sshengine.common.transport.signature.SignatureFactories;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.github.grantchan.sshengine.util.publickey.decoder.PublicKeyDecoder;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.List;

import static io.github.grantchan.sshengine.util.buffer.Bytes.md5;
import static io.github.grantchan.sshengine.util.buffer.Bytes.sha256;

public class ClientDhGroup extends AbstractLogger implements KexGroup {

  private final MessageDigest md;

  protected final Kex kex;
  protected final ClientSession session;

  private byte expect = SshMessage.SSH_MSG_KEXDH_INIT;

  public ClientDhGroup(MessageDigest md, Kex kex, ClientSession session) {
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
  public void handle(int cmd, ByteBuf msg) throws SshException {
    logger.debug("{} Handling key exchange message - {} ...", session, SshMessage.from(cmd));

    if (cmd == SshMessage.SSH_MSG_KEXDH_INIT && expect == SshMessage.SSH_MSG_KEXDH_INIT) {
      handleDhInit(msg);

      expect = SshMessage.SSH_MSG_KEXDH_REPLY;
    } else if (cmd == SshMessage.SSH_MSG_KEXDH_REPLY && expect == SshMessage.SSH_MSG_KEXDH_REPLY) {
      handleDhReply(msg);

      session.requestKexNewKeys();
    } else {
      throw new SshException(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
          "Invalid key exchange message, expect: SSH_MSG_KEXDH_INIT, actual: " +
              SshMessage.from(cmd));
    }
  }

  private void handleDhInit(ByteBuf msg) {

    /*
     * RFC 4253:
     * First, the client sends the following:
     *   byte    SSH_MSG_KEXDH_INIT
     *   mpint   e
     */
    BigInteger e = kex.getPubKey();
    if (e == null) {
      throw new IllegalStateException("Key exchange is not initialized");
    }

    session.requestKexDhInit(e);
  }

  private void handleDhReply(ByteBuf msg) throws SshException {
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
    byte[] k_s = ByteBufIo.readBytes(msg);
    logger.debug("{} Host RSA public key fingerprint MD5: {}, SHA256: {}",
        session, md5(k_s), sha256(k_s));
    // Client user needs to verify the hash value of k_s(public key) of the server here

    BigInteger e = ByteBufIo.readMpInt(msg);
    kex.receivedPubKey(e);

    byte[] sigH = ByteBufIo.readBytes(msg);

    String v_c = session.getClientId();
    String v_s = session.getServerId();
    byte[] i_c = session.getRawC2sKex();
    byte[] i_s = session.getRawS2cKex();

    PublicKey pubKey = null;
    try {
      pubKey = PublicKeyDecoder.ALL.decode(k_s);
    } catch (IOException | GeneralSecurityException | IllegalAccessException e1) {
      e1.printStackTrace();
    }

    byte[] h_s = Bytes.concat(
        Bytes.joinWithLength(v_c, v_s),
        Bytes.joinWithLength(i_c, i_s, k_s),
        Bytes.joinWithLength(kex.getPubKey(), e, kex.getSecretKey())
    );

    md.update(h_s);
    byte[] h = md.digest();
    session.setRawId(h);

    List<String> kexParams = session.getKexInit();

    Signature verif = SignatureFactories.create(kexParams.get(KexProposal.Param.SERVER_HOST_KEY), pubKey);
    if (verif == null) {
      throw new IllegalArgumentException("Unknown signature: " +
          kexParams.get(KexProposal.Param.SERVER_HOST_KEY));
    }

    try {
      verif.update(h);
      if (!verif.verify(sigH)) {
        throw new SshException(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
            "Failed to verify key exchange signature.");
      }
    } catch (SignatureException e1) {
      e1.printStackTrace();
    }

    logger.debug("{} KEX process completed after SSH_MSG_KEXDH_REPLY", session);
  }
}
