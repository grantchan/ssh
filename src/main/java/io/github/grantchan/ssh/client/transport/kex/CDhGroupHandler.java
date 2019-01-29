package io.github.grantchan.ssh.client.transport.kex;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.kex.KexInitParam;
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.github.grantchan.ssh.common.transport.signature.Signature;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;
import io.github.grantchan.ssh.server.transport.kex.KexHandler;
import io.github.grantchan.ssh.util.buffer.SshByteBuf;
import io.github.grantchan.ssh.util.key.decoder.RSAPublicKeyDecoder;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.List;

public class CDhGroupHandler extends KexHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private byte expect = SshMessage.SSH_MSG_KEXDH_INIT;

  public CDhGroupHandler(MessageDigest md, KeyExchange kex, Session session) {
    super(md, kex, session);
  }

  @Override
  public void handleMessage(int cmd, ByteBuf msg) throws IOException {
    logger.debug("Handling key exchange message - {} ...", SshMessage.from(cmd));

    if (cmd == SshMessage.SSH_MSG_KEXDH_INIT &&
        expect == SshMessage.SSH_MSG_KEXDH_INIT) {
      handleDhInit(msg);

      expect = SshMessage.SSH_MSG_KEXDH_REPLY;
    } else if (cmd == SshMessage.SSH_MSG_KEXDH_REPLY &&
               expect == SshMessage.SSH_MSG_KEXDH_REPLY) {
      handleDhReply(msg);

      expect = SshMessage.SSH_MSG_NEWKEYS;
    } else {
      throw new IOException("Invalid key exchange message, expect: " + SshMessage.from(expect) +
                            ", actual: " + SshMessage.from(cmd));
    }
  }

  private void handleDhInit(ByteBuf msg) {

    /*
     * RFC 4253:
     * First, the client sends the following:
     *   byte    SSH_MSG_KEXDH_INIT
     *   mpint   e
     */
    byte[] e = kex.getPubKey();
    if (e == null) {
      throw new IllegalStateException("Key exchange is not initialized");
    }

    session.requestKexDhInit(e);
  }

  private void handleDhReply(ByteBuf msg) throws IOException {

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
    byte[] k_s = SshByteBuf.readBytes(msg);
    // Client user needs to verify the hash value of k_s(public key) of the server here

    byte[] e = SshByteBuf.readBytes(msg);
    kex.receivedPubKey(e);

    byte[] sigH = SshByteBuf.readBytes(msg);

    byte[] v_c = session.getClientId().getBytes(StandardCharsets.UTF_8);
    byte[] v_s = session.getServerId().getBytes(StandardCharsets.UTF_8);
    byte[] i_c = session.getC2sKex();
    byte[] i_s = session.getS2cKex();

    PublicKey pubKey = null;
    try {
      pubKey = RSAPublicKeyDecoder.getInstance().decode(k_s);
    } catch (IOException | GeneralSecurityException e1) {
      e1.printStackTrace();
    }

    ByteBuf buf = session.createBuffer();

    SshByteBuf.writeBytes(buf, v_c);
    SshByteBuf.writeBytes(buf, v_s);
    SshByteBuf.writeBytes(buf, i_c);
    SshByteBuf.writeBytes(buf, i_s);
    SshByteBuf.writeBytes(buf, k_s);
    SshByteBuf.writeMpInt(buf, kex.getPubKey());
    SshByteBuf.writeMpInt(buf, e);
    SshByteBuf.writeMpInt(buf, kex.getSecretKey());
    byte[] h_s = new byte[buf.readableBytes()];
    buf.readBytes(h_s);

    md.update(h_s);
    byte[] h = md.digest();

    List<String> kexParams = session.getKexInit();

    Signature verif = SignatureFactories.create(kexParams.get(KexInitParam.SERVER_HOST_KEY), pubKey);
    if (verif == null) {
      throw new IOException("Unknown signature: " + kexParams.get(KexInitParam.SERVER_HOST_KEY));
    }

    try {
      verif.update(h);
      if (!verif.verify(sigH)) {
        throw new IOException("Key exchange signature verification failed.");
      }
    } catch (SignatureException e1) {
      e1.printStackTrace();
    }
  }
}
