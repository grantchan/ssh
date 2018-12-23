package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.github.grantchan.ssh.trans.signature.Signature;
import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class DhKexHandler extends KexHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public DhKexHandler(MessageDigest md, DHGroupData dhgd, Session session) {
    super(md, session);

    this.dh = new DH(dhgd.P(), dhgd.G());
  }

  @Override
  public void handleMessage(int cmd, ByteBuf req) throws IOException {
    logger.debug("Handling key exchange message - {} ...", SshMessage.from(cmd));

    if (cmd != SshMessage.SSH_MSG_KEXDH_INIT) {
      throw new IOException("Invalid key exchange stage packet, expected: SSH_MSG_KEXDH_INIT," +
                            " actual: " + SshMessage.from(cmd));
    }

    /*
     * RFC 4419:
     * The client sends SSH_MSG_KEX_DH_GEX_INIT
     *   byte    SSH_MSG_KEX_DH_GEX_INIT
     *   mpint   e
     */
    byte[] e = ByteBufUtil.readBytes(req);
    dh.receivedPubKey(e);

    /*
     * RFC 4419:
     * The server responds with SSH_MSG_KEX_DH_GEX_REPLY:
     *   byte    SSH_MSG_KEX_DH_GEX_REPLY
     *   string  server public host key and certificates (K_S)
     *   mpint   f
     *   string  signature of H
     *
     * The hash H is computed as the HASH hash of the concatenation of the
     * following:
     *
     *   string  V_C, the client's version string (CR and NL excluded)
     *   string  V_S, the server's version string (CR and NL excluded)
     *   string  I_C, the payload of the client's SSH_MSG_KEXINIT
     *   string  I_S, the payload of the server's SSH_MSG_KEXINIT
     *   string  K_S, the host key
     *   uint32  min, minimal size in bits of an acceptable group
     *   uint32  n, preferred size in bits of the group the server will send
     *   uint32  max, maximal size in bits of an acceptable group
     *   mpint   p, safe prime
     *   mpint   g, generator for subgroup
     *   mpint   e, exchange value sent by the client
     *   mpint   f, exchange value sent by the server
     *   mpint   K, the shared secret
     */
    byte[] v_c = session.getClientVer().getBytes(StandardCharsets.UTF_8);
    byte[] v_s = session.getServerVer().getBytes(StandardCharsets.UTF_8);
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

    ByteBufUtil.writeUtf8(reply, "ssh-rsa");
    RSAPublicKey pubKey = ((RSAPublicKey) kp.getPublic());
    ByteBufUtil.writeMpInt(reply, pubKey.getPublicExponent());
    ByteBufUtil.writeMpInt(reply, pubKey.getModulus());

    byte[] k_s = new byte[reply.readableBytes()];
    reply.readBytes(k_s);

    reply.clear();
    ByteBufUtil.writeBytes(reply, v_c);
    ByteBufUtil.writeBytes(reply, v_s);
    ByteBufUtil.writeBytes(reply, i_c);
    ByteBufUtil.writeBytes(reply, i_s);
    ByteBufUtil.writeBytes(reply, k_s);
    ByteBufUtil.writeMpInt(reply, e);
    ByteBufUtil.writeMpInt(reply, dh.getPubKey());
    ByteBufUtil.writeMpInt(reply, dh.getSecretKey());

    byte[] h_s = new byte[reply.readableBytes()];
    reply.readBytes(h_s);

    md.update(h_s, 0, h_s.length);
    h = md.digest();

    List<String> kexParams = session.getKexParams();

    Signature sig = BuiltinSignatureFactory.create(kexParams.get(KexParam.SERVER_HOST_KEY),
        kp.getPrivate());
    if (sig == null) {
      throw new IOException("Unknown signature: " + KexParam.SERVER_HOST_KEY);
    }

    try {
      sig.update(h);

      reply.clear();
      ByteBufUtil.writeUtf8(reply, kexParams.get(KexParam.SERVER_HOST_KEY));
      ByteBufUtil.writeBytes(reply, sig.sign());
    } catch (SignatureException ex) {
      ex.printStackTrace();
    }

    byte[] sigH = new byte[reply.readableBytes()];
    reply.readBytes(sigH);

    session.replyKexDhReply(k_s, dh.getPubKey(), sigH);
    session.requestKexNewKeys();
  }
}
