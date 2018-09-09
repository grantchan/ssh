package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.util.SshByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static io.github.grantchan.ssh.common.SshConstant.*;
import static io.github.grantchan.ssh.common.SshConstant.SSH_MSG_NEWKEYS;
import static io.github.grantchan.ssh.common.SshConstant.SSH_PACKET_HEADER_LENGTH;

public class Kex {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private MessageDigest md;

  private int min; // minimal size in bits of an acceptable group
  private int n;   // preferred size in bits of the group the server will send
  private int max; // maximal size in bits of an acceptable group

  private DHSpec dh;
  private byte[] h = null;
  private Session session;

  public Kex(MessageDigest md) {
    this.md = md;
  }

  public void setSession(Session session) {
    this.session = session;
  }

  public void handleKexMessage(ChannelHandlerContext ctx, int cmd, ByteBuf msg) {
    logger.info("Handling key exchange message - {} ...", cmd);

    switch(cmd) {
      case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
        handleDhGexRequestOld(ctx, msg);
        break;

      case SSH_MSG_KEX_DH_GEX_REQUEST:
        handleDhGexGroup(ctx, msg);
        break;

      case SSH_MSG_KEX_DH_GEX_INIT:
        handleDhGexInit(ctx, msg);
        break;

    }
  }

  protected void handleDhGexRequestOld(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * The client sends SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
     *   byte     SSH_MSG_KEX_DH_GEX_REQUEST_OLD
     *   uint32   n, preferred size in bits of the group the server will send
     */
    n = msg.readInt();
    min = -1;
    max = -1;

    /*
     * The server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     *   byte     SSH_MSG_KEX_DH_GEX_GROUP
     *   mpint    p, safe prime
     *   mpint    g, generator for subgroup in GF(p)
     */
    handleDhGexGroup(ctx, min, n, max);
  }

  protected void handleDhGexGroup(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * The client sends SSH_MSG_KEX_DH_GEX_REQUEST:
     *   byte     SSH_MSG_KEX_DH_GEX_REQUEST
     *   uint32   min, minimal size in bits of an acceptable group
     *   uint32   n,   preferred size in bits of the group the server will send
     *   uint32   max, maximal size in bits of an acceptable group
     */
    min = msg.readInt();
    n = msg.readInt();
    max = msg.readInt();

    /*
     * The server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     *   byte     SSH_MSG_KEX_DH_GEX_GROUP
     *   mpint    p, safe prime
     *   mpint    g, generator for subgroup in GF(p)
     */
    handleDhGexGroup(ctx, min, n, max);
  }

  protected void handleDhGexGroup(ChannelHandlerContext ctx, int min, int n, int max) {
    dh = getDH(min, n, max);

    ByteBuf pg = ctx.alloc().buffer();
    pg.writerIndex(SSH_PACKET_HEADER_LENGTH);
    pg.readerIndex(SSH_PACKET_HEADER_LENGTH);

    pg.writeByte(SSH_MSG_KEX_DH_GEX_GROUP);

    SshByteBufUtil.writeMpInt(pg, dh.getP());
    SshByteBufUtil.writeMpInt(pg, dh.getG());

    ctx.channel().writeAndFlush(pg);
  }

  private DHSpec getDH(int min, int n, int max) {
    BigInteger p;
    if (n == 2048) {
      p = new BigInteger("CF14CEC123C83DF3CF6EA7A5A4C03FB0B1542DCAA09DDFC11B5F8AD4468D28A193BC550E267308712F30688BB9559F68224F1262331E900F9F89E04A7CE2A0126FB2B69008B71219ED6109E6E353A893977179CD9CC15C980D8921EA61C56FD36752819816E7D658F22F2FC1698C30392E4BB97023B0D9943B13286CAC1C351C342341CCE3234D8C5C70B6369158D6DEA23037045D19C690FAF4A7F50750A2ECEF42223DA315999847C624A5BCAA0CF634F0F827DC14762E4F63827A15411BC8CFF3BCAAFD3C5D69D9D033B5D99FEF178881960E09C085819EF2255BD0715378E051EA56AB9341F46698FAF86B736C745E1B152082251CBB6969E8F12F909B43", 16);
    } else if (n == 4096) {
      p = new BigInteger("C082C6D5214016F2748DBC7D756DF9A769F0FCA6A162ACAF8DF354C82684FA5D6471B940AB4283F6BF477624A7A880AE06B1AB60E0EA339B0875244F28869D5661A0DC75425A889F6BD03E937983F896DB02E3E5D782F68B7463E88DEC396ED8C03F7F832DD1D1056EAC8444AEB64C73DB754BAAFCB4CBD642CD5C6257794434494E8A2DFBA7EAA108935B4045CB49EE0E6A2EB6E75E72CFF6B9B7BE69A61D44511EE6CA207C43012CE8DA86C293AD25FE9B3610806DF16CEE48537784CCF04C2A3AA5F1CE5CA302E3D5B07B925B32910A72CCDAC361582836287AF4E7D20A0C314EC58292EDC1C67E9DEE7FC0A88A1ADCE1C6EC45D2398E523858892086888B60E12CD3374A454BF59890A98B4D7A784B64D809CB59207CF9360193C920896F731DA355CABDFCBDF827EFB03D300D94AB207C52B00E78146680A793F3EA65D4428F1BC2456AACDC99985DB10934182F431195FB517DC37F643360EC34859E86D49602E1A2454204982F4AECBC4C7411322E4FCD4AE8EE5076B0D4707E61878EF568FE50AC8B4786DDC2AD7391B8FA9D23651A5D695DF30A4C29CEFB57ABC21DE062D4C16E345AB416CCF69B3AA2C8076BD7730DDD2AF3249D7AA5D0613439F38DC97536758BF31687122B6D5FC32AEA7E306020A5DA4CBC719F9BFCB1E17EE1968D21ECCBAAB24923B7D7FFF30714C4713472C0BBF4D846D39E0215C8915583", 16);
    } else {
      throw new IllegalArgumentException();
    }
    BigInteger g = new BigInteger("2", 16);

    return new DHSpec(p, g);
  }

  private void handleDhGexInit(ChannelHandlerContext ctx, ByteBuf req) {
    /*
     * The client sends SSH_MSG_KEX_DH_GEX_INIT
     *   byte    SSH_MSG_KEX_DH_GEX_INIT
     *   mpint   e
     */
    byte[] e = SshByteBufUtil.readBytes(req);
    dh.receivedPubKey(e);

    /*
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
    byte[] i_c = session.getClientKexInit();
    byte[] i_s = session.getServerKexInit();

    handleKexDhGexReply(ctx, v_c, v_s, i_c, i_s);
    requestKexNewKeys(ctx);
  }

  private void handleKexDhGexReply(ChannelHandlerContext ctx, byte[] v_c, byte[] v_s, byte[] i_c, byte[] i_s) {
    KeyPairGenerator kpg = null;
    try {
      kpg = KeyPairGenerator.getInstance("RSA");
    } catch (NoSuchAlgorithmException e1) {
      e1.printStackTrace();
    }
    assert kpg != null;
    KeyPair kp = kpg.generateKeyPair();

    ByteBuf reply = ctx.alloc().buffer();

    SshByteBufUtil.writeUtf8(reply, "ssh-rsa");
    RSAPublicKey pubKey = ((RSAPublicKey) kp.getPublic());
    SshByteBufUtil.writeMpInt(reply, pubKey.getPublicExponent());
    SshByteBufUtil.writeMpInt(reply, pubKey.getModulus());

    byte[] k_s = new byte[reply.readableBytes()];
    reply.readBytes(k_s);

    reply.clear();
    SshByteBufUtil.writeBytes(reply, v_c);
    SshByteBufUtil.writeBytes(reply, v_s);
    SshByteBufUtil.writeBytes(reply, i_c);
    SshByteBufUtil.writeBytes(reply, i_s);
    SshByteBufUtil.writeBytes(reply, k_s);

    if (min == -1 || max == -1) { // old request
      reply.writeInt(n);
    } else {
      reply.writeInt(min);
      reply.writeInt(n);
      reply.writeInt(max);
    }

    SshByteBufUtil.writeMpInt(reply, dh.getP());
    SshByteBufUtil.writeMpInt(reply, dh.getG());
    SshByteBufUtil.writeMpInt(reply, dh.getReceivedPubKey());
    SshByteBufUtil.writeMpInt(reply, dh.getPubKey());
    SshByteBufUtil.writeMpInt(reply, dh.getSecretKey());
    byte[] h_s = new byte[reply.readableBytes()];
    reply.readBytes(h_s);

    md.update(h_s, 0, h_s.length);
    h = md.digest();

    List<String> kexInit = session.getKexInitResult();

    Signature sig = null;
    try {
      sig = Factory.create(SignatureFactory.values, kexInit.get(KexAlgorithm.SERVER_HOST_KEY));
    } catch (Exception e) {
      e.printStackTrace();
    }
    assert sig != null;
    try {
      sig.initSign(kp.getPrivate());
      sig.update(h);

      reply.clear();
      SshByteBufUtil.writeUtf8(reply, kexInit.get(KexAlgorithm.SERVER_HOST_KEY));
      SshByteBufUtil.writeBytes(reply, sig.sign());
    } catch (SignatureException | InvalidKeyException e1) {
      e1.printStackTrace();
    }

    byte[] sigH = new byte[reply.readableBytes()];
    reply.readBytes(sigH);

    reply.clear();
    reply.writerIndex(SSH_PACKET_HEADER_LENGTH);
    reply.readerIndex(SSH_PACKET_HEADER_LENGTH);
    reply.writeByte(SSH_MSG_KEX_DH_GEX_REPLY);

    SshByteBufUtil.writeBytes(reply, k_s);
    SshByteBufUtil.writeBytes(reply, dh.getPubKey());
    SshByteBufUtil.writeBytes(reply, sigH);

    ctx.channel().writeAndFlush(reply);
  }

  private void requestKexNewKeys(ChannelHandlerContext ctx) {
    int bsize = 8;
    int len   = Byte.SIZE + SSH_PACKET_HEADER_LENGTH;
    int pad   = (-len) & (bsize - 1);
    if (pad < bsize) {
      pad += bsize;
    }
    len += pad - 4;

    ByteBuf newKeys = Unpooled.wrappedBuffer(new byte[len + Byte.SIZE]);

    newKeys.writerIndex(SSH_PACKET_HEADER_LENGTH);
    newKeys.readerIndex(SSH_PACKET_HEADER_LENGTH);
    newKeys.writeByte(SSH_MSG_NEWKEYS);

    ctx.channel().writeAndFlush(newKeys);
  }
}
