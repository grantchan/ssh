package io.github.grantchan.ssh.server.transport.kex;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.digest.DigestFactories;
import io.github.grantchan.ssh.common.transport.kex.KexInitParam;
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.github.grantchan.ssh.common.transport.signature.Signature;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;
import io.github.grantchan.ssh.util.buffer.SshByteBuf;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

public class SDhGroupHandler extends KexHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public SDhGroupHandler(MessageDigest md, KeyExchange kex, Session session) {
    super(md, kex, session);
  }

  @Override
  public void handleMessage(int cmd, ByteBuf req) throws IOException {
    logger.debug("Handling key exchange message - {} ...", SshMessage.from(cmd));

    if (cmd != SshMessage.SSH_MSG_KEXDH_INIT) {
      throw new IOException("Invalid key exchange stage packet, expected: SSH_MSG_KEXDH_INIT" +
                            ", actual: " + SshMessage.from(cmd));
    }

    /*
     * RFC 4253:
     * First, the client sends the following:
     *   byte    SSH_MSG_KEXDH_INIT
     *   mpint   e
     */
    byte[] e = SshByteBuf.readBytes(req);
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
    byte[] v_c = session.getClientId().getBytes(StandardCharsets.UTF_8);
    byte[] v_s = session.getServerId().getBytes(StandardCharsets.UTF_8);
    byte[] i_c = session.getC2sKex();
    byte[] i_s = session.getS2cKex();

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("RSA");
    } catch (NoSuchAlgorithmException e1) {
      e1.printStackTrace();
      return;
    }
    KeyPair kp = kpg.generateKeyPair();

    ByteBuf reply = session.createBuffer();

    SshByteBuf.writeUtf8(reply, "ssh-rsa");
    RSAPublicKey pubKey = ((RSAPublicKey) kp.getPublic());
    SshByteBuf.writeMpInt(reply, pubKey.getPublicExponent());
    SshByteBuf.writeMpInt(reply, pubKey.getModulus());

    byte[] k_s = new byte[reply.readableBytes()];
    reply.readBytes(k_s);

    logger.debug("Host RSA public key fingerprint MD5:{}, SHA256:{}", md5(k_s), sha256(k_s));

    reply.clear();
    SshByteBuf.writeBytes(reply, v_c);
    SshByteBuf.writeBytes(reply, v_s);
    SshByteBuf.writeBytes(reply, i_c);
    SshByteBuf.writeBytes(reply, i_s);
    SshByteBuf.writeBytes(reply, k_s);
    SshByteBuf.writeMpInt(reply, e);
    SshByteBuf.writeMpInt(reply, kex.getPubKey());
    SshByteBuf.writeMpInt(reply, kex.getSecretKey());

    byte[] h_s = new byte[reply.readableBytes()];
    reply.readBytes(h_s);

    md.update(h_s, 0, h_s.length);
    h = md.digest();

    List<String> kexParams = session.getKexInit();

    Signature sig = SignatureFactories.create(kexParams.get(KexInitParam.SERVER_HOST_KEY),
        kp.getPrivate());
    if (sig == null) {
      throw new IOException("Unknown signature: " + KexInitParam.SERVER_HOST_KEY);
    }

    try {
      sig.update(h);

      reply.clear();
      SshByteBuf.writeUtf8(reply, kexParams.get(KexInitParam.SERVER_HOST_KEY));
      SshByteBuf.writeBytes(reply, sig.sign());
    } catch (SignatureException ex) {
      ex.printStackTrace();
    }

    byte[] sigH = new byte[reply.readableBytes()];
    reply.readBytes(sigH);

    session.replyKexDhReply(k_s, kex.getPubKey(), sigH);
    session.requestKexNewKeys();
  }

  private byte[] fingerPrint(byte[] data, MessageDigest md) {
    if (data == null) {
      throw new IllegalArgumentException("Invalid parameter - data is null");
    }
    if (md == null) {
      throw new IllegalArgumentException("Invalid parameter - message digest is null");
    }

    md.update(data);

    return md.digest();
  }

  private String md5(byte[] key) {
    if (key == null) {
      throw new IllegalArgumentException("Invalid key parameter - key is null");
    }

    byte[] data = fingerPrint(key, Objects.requireNonNull(DigestFactories.md5.create()));

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < data.length; i++) {
      byte b = data[i];
      sb.append("0123456789abcdef".charAt((b >> 4) & 0x0F));
      sb.append("0123456789abcdef".charAt(b & 0x0F));
      if (i < data.length - 1) {
        sb.append(":");
      }
    }
    return sb.toString();
  }

  private String sha256(byte[] key) {
    if (key == null) {
      throw new IllegalArgumentException("Invalid key parameter - key is null");
    }

    byte[] data = fingerPrint(key, Objects.requireNonNull(DigestFactories.sha256.create()));

    Base64.Encoder base64 = Base64.getEncoder();

    return base64.encodeToString(data).replaceAll("=", "");
  }
}
