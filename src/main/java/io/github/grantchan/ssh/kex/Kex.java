package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshConstant;
import io.github.grantchan.ssh.util.SshByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class Kex {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private MessageDigest md;

  private int min; // minimal size in bits of an acceptable group
  private int n;   // preferred size in bits of the group the server will send
  private int max; // maximal size in bits of an acceptable group

  private DH dh;
  private byte[] h = null;
  private Session session;

  public Kex(MessageDigest md) {
    this.md = md;
  }

  public void setSession(Session session) {
    this.session = session;
  }

  public void handleKexMessage(ChannelHandlerContext ctx, int cmd, ByteBuf msg) {
    logger.debug("Handling key exchange message - {} ...", SshConstant.messageName(cmd));

    switch(cmd) {
      case SshConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
        handleDhGexRequestOld(ctx, msg);
        break;

      case SshConstant.SSH_MSG_KEX_DH_GEX_REQUEST:
        handleDhGexRequest(ctx, msg);
        break;

      case SshConstant.SSH_MSG_KEX_DH_GEX_INIT:
        handleDhGexInit(ctx, msg);
        break;

      case SshConstant.SSH_MSG_NEWKEYS:
        handleNewKeys(ctx, msg);
        break;

    }
  }

  protected void handleDhGexRequestOld(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * RFC 4419:
     * The client sends SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
     *   byte     SSH_MSG_KEX_DH_GEX_REQUEST_OLD
     *   uint32   n, preferred size in bits of the group the server will send
     */
    n = msg.readInt();
    min = -1;
    max = -1;

    /*
     * RFC 4419:
     * The server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     *   byte     SSH_MSG_KEX_DH_GEX_GROUP
     *   mpint    p, safe prime
     *   mpint    g, generator for subgroup in GF(p)
     */
    replyDhGexGroup(ctx, min, n, max);
  }

  protected void handleDhGexRequest(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * RFC 4419:
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
     * RFC 4419:
     * The server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     *   byte     SSH_MSG_KEX_DH_GEX_GROUP
     *   mpint    p, safe prime
     *   mpint    g, generator for subgroup in GF(p)
     */
    replyDhGexGroup(ctx, min, n, max);
  }

  protected void replyDhGexGroup(ChannelHandlerContext ctx, int min, int n, int max) {
    dh = getDH(min, n, max);

    ByteBuf pg = ctx.alloc().buffer();
    pg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    pg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);

    pg.writeByte(SshConstant.SSH_MSG_KEX_DH_GEX_GROUP);

    SshByteBufUtil.writeMpInt(pg, dh.getP());
    SshByteBufUtil.writeMpInt(pg, dh.getG());

    logger.debug("Replying SSH_MSG_KEX_DH_GEX_GROUP...");
    ctx.channel().writeAndFlush(pg);
  }

  private DH getDH(int min, int n, int max) {
    BigInteger p;
    if (n == 2048) {
      p = new BigInteger("CF14CEC123C83DF3CF6EA7A5A4C03FB0B1542DCAA09DDFC11B5F8AD4468D28A193BC550E267308712F30688BB9559F68224F1262331E900F9F89E04A7CE2A0126FB2B69008B71219ED6109E6E353A893977179CD9CC15C980D8921EA61C56FD36752819816E7D658F22F2FC1698C30392E4BB97023B0D9943B13286CAC1C351C342341CCE3234D8C5C70B6369158D6DEA23037045D19C690FAF4A7F50750A2ECEF42223DA315999847C624A5BCAA0CF634F0F827DC14762E4F63827A15411BC8CFF3BCAAFD3C5D69D9D033B5D99FEF178881960E09C085819EF2255BD0715378E051EA56AB9341F46698FAF86B736C745E1B152082251CBB6969E8F12F909B43", 16);
    } else if (n == 4096) {
      p = new BigInteger("C082C6D5214016F2748DBC7D756DF9A769F0FCA6A162ACAF8DF354C82684FA5D6471B940AB4283F6BF477624A7A880AE06B1AB60E0EA339B0875244F28869D5661A0DC75425A889F6BD03E937983F896DB02E3E5D782F68B7463E88DEC396ED8C03F7F832DD1D1056EAC8444AEB64C73DB754BAAFCB4CBD642CD5C6257794434494E8A2DFBA7EAA108935B4045CB49EE0E6A2EB6E75E72CFF6B9B7BE69A61D44511EE6CA207C43012CE8DA86C293AD25FE9B3610806DF16CEE48537784CCF04C2A3AA5F1CE5CA302E3D5B07B925B32910A72CCDAC361582836287AF4E7D20A0C314EC58292EDC1C67E9DEE7FC0A88A1ADCE1C6EC45D2398E523858892086888B60E12CD3374A454BF59890A98B4D7A784B64D809CB59207CF9360193C920896F731DA355CABDFCBDF827EFB03D300D94AB207C52B00E78146680A793F3EA65D4428F1BC2456AACDC99985DB10934182F431195FB517DC37F643360EC34859E86D49602E1A2454204982F4AECBC4C7411322E4FCD4AE8EE5076B0D4707E61878EF568FE50AC8B4786DDC2AD7391B8FA9D23651A5D695DF30A4C29CEFB57ABC21DE062D4C16E345AB416CCF69B3AA2C8076BD7730DDD2AF3249D7AA5D0613439F38DC97536758BF31687122B6D5FC32AEA7E306020A5DA4CBC719F9BFCB1E17EE1968D21ECCBAAB24923B7D7FFF30714C4713472C0BBF4D846D39E0215C8915583", 16);
    } else if (n == 8192) {
      p = new BigInteger("D3584411656A5311623FF0D234C21F198B128AE78662AB22596F7FDB40C949394BF6CEDA3209BEA8F64DB8F6A39F3DCAA89D3EEA0821F7DA8938F20089CA1C8067BA93163268C7CAE191760CCF8B5FDC0E4168B9986E32CC396B17F69A9EF032BA06AB969DFF1BDA3B8F5A6A8A0592AAEC5B5BB1A604A8C0589DC7DE99C87E992BE1A2F74D817AD5424E8AE14808F09213B1C268A47196E5013D75CAA5F8C76B6B5A951D48D0F8E066360E409D6076D99A3AF7CAB631041B6DD14BBF9C0E0BC39B66542C9D3C7E98C97E3A1C08C25047963D6F5A0D05EB3684B3B5B31379838B1AE1D05677898A3FC986F2D01CD44A25D46AD8D9626774DD8AFE4723987E7B87AFCD1560FA3931A760C8E96C58552A1B6953441F52F4F8A49C0597C9F79B24D9650C4C901A4E862458F6CF8451D445A1A9330C65A0CD00C9254A419BBF72B4C66459B4E50CC2849782FFA6D3C9EEDFE7F7983E94A0499F8AC90F41081BB6756D22713A4D4FC61784410192827AC6ECB043870E593EB71EEDA34BAEC1CCBFB94E746367E19732FCAA22AB9736093BE512D38C293C77C175B977B0590C4D72D8CCD8CC962A77C9AEA280B43BBB7669447AF02539857442AE168E77560184CDCC495D99DECEAE61A72129A44A0A5AE9D7779B157C7F262AF465D2F6DFFD937ED535E6CAF2AF9C9FEC8C499EF734FAE66A075EA63B8DC37C0A8F1E07031C3D9EADA10D3E7ED2B7487A9E35DD5A14A147351BC5AB87AAC28D76B3CEA7CC2EF8C3F783A325C5926E48839087E123CA096623C77ACCD0509D38849D3C3AAF499905065E87F64B5BC390D9763E5FF00B80432C0747AC6753B9439ED5476C486A6B44A2A933533198700168A49C6020BC4ACDC1513604B8EAE7B7920DF6C4A963E93CEB054D5380689DA6F81E0A084C499F28D7623F9634AE2C3FF00CC267DAB9A84EB81F54470923C64852CCD7B39178BF750E9268780F317D0C6F059A401F880CEC81F8E7C502082824E0F7F0673B137DAEE72DB42BD6B72946905E0D0870B1055F0F9514FD85E0C05BA82C7244FA88CD5BFD7EF64A7C29385CE17744C2B8367EB1A9B195492B0B14A2BBC640872890B717F8B13F6AAAB8215721723C8CE036019163F5222CBAFF5DE69D4004545A60207248208C67B5C9E097B2B9EB61CA61E205E8F03AB13F08AB7C85A1BC90E143E82879E39280D825BBA3E5B3E4F61810D6760D702D97EECCDFE68F5643D0263C38D213986082EF1113508C42AE38F29F8E7A80EF785A6C57F9CE8D1F884C63A2551AE2AD80DB3A372D169596ADBFCD27BD44D127CAE086706842FB4F52420D10CD08D472AEDC5B98CD788BCB63D0CE9B04715B355B622D69AD1F5C1215DEE5B0EB8CB47A27A88ED10C5CEF6B462A65F701AF0AD828D41932E23D3E1D7A86083E3554F092D8EF81454B7B60BE78B129011D3EC8CB", 16);
    } else {
      throw new IllegalArgumentException();
    }
    BigInteger g = new BigInteger("2", 16);

    return new DH(p, g);
  }

  private void handleDhGexInit(ChannelHandlerContext ctx, ByteBuf req) {
    /*
     * RFC 4419:
     * The client sends SSH_MSG_KEX_DH_GEX_INIT
     *   byte    SSH_MSG_KEX_DH_GEX_INIT
     *   mpint   e
     */
    byte[] e = SshByteBufUtil.readBytes(req);
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
    byte[] i_c = session.getClientKexInit();
    byte[] i_s = session.getServerKexInit();

    replyKexDhGexReply(ctx, v_c, v_s, i_c, i_s);
    requestKexNewKeys(ctx);
  }

  private void replyKexDhGexReply(ChannelHandlerContext ctx, byte[] v_c, byte[] v_s, byte[] i_c, byte[] i_s) {
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

    List<String> kexParams = session.getKexParams();

    Signature sig = null;
    try {
      sig = Factory.create(SignatureFactory.values, kexParams.get(KexParam.SERVER_HOST_KEY));
    } catch (Exception e) {
      e.printStackTrace();
    }
    assert sig != null;
    try {
      sig.initSign(kp.getPrivate());
      sig.update(h);

      reply.clear();
      SshByteBufUtil.writeUtf8(reply, kexParams.get(KexParam.SERVER_HOST_KEY));
      SshByteBufUtil.writeBytes(reply, sig.sign());
    } catch (SignatureException | InvalidKeyException e1) {
      e1.printStackTrace();
    }

    byte[] sigH = new byte[reply.readableBytes()];
    reply.readBytes(sigH);

    reply.clear();
    reply.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    reply.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    reply.writeByte(SshConstant.SSH_MSG_KEX_DH_GEX_REPLY);

    SshByteBufUtil.writeBytes(reply, k_s);
    SshByteBufUtil.writeBytes(reply, dh.getPubKey());
    SshByteBufUtil.writeBytes(reply, sigH);

    logger.debug("Replying SSH_MSG_KEX_DH_GEX_REPLY...");
    ctx.channel().writeAndFlush(reply);
  }

  private void requestKexNewKeys(ChannelHandlerContext ctx) {
    int bsize = 8;
    int len   = Byte.SIZE + SshConstant.SSH_PACKET_HEADER_LENGTH;
    int pad   = (-len) & (bsize - 1);
    if (pad < bsize) {
      pad += bsize;
    }
    len += pad - 4;

    ByteBuf newKeys = Unpooled.wrappedBuffer(new byte[len + Byte.SIZE]);

    newKeys.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    newKeys.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    newKeys.writeByte(SshConstant.SSH_MSG_NEWKEYS);

    logger.debug("Requesting SSH_MSG_NEWKEYS...");
    ctx.channel().writeAndFlush(newKeys);
  }

  protected void handleNewKeys(ChannelHandlerContext ctx, ByteBuf msg) {
    byte[] id = h;
    StringBuilder sb = new StringBuilder();
    for (byte b : id) {
      sb.append("0123456789abcdef".charAt((b >> 4) & 0x0F));
      sb.append("0123456789abcdef".charAt(b & 0x0F));
      sb.append(":");
    }
    logger.info("SSH_MSG_NEWKEYS: {}", sb.toString());

    ByteBuf buf = ctx.alloc().buffer();
    byte[]  k   = dh.getSecretKey();
    SshByteBufUtil.writeMpInt(buf, k);
    buf.writeBytes(id);
    buf.writeByte((byte) 0x41);
    buf.writeBytes(id);

    int readableBytes = buf.readableBytes();
    byte[] array = new byte[readableBytes];
    buf.readBytes(array);

    int j = readableBytes - id.length - 1;

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

    List<String> kp = session.getKexParams();

    try {
      // server to client cipher
      CipherFactory cf;
      cf = CipherFactory.fromName(kp.get(KexParam.ENCRYPTION_S2C));
      assert cf != null;
      e_s2c = hashKey(e_s2c, cf.getBlkSize(), k);
      Cipher s2cCip = cf.create(e_s2c, iv_s2c, Cipher.ENCRYPT_MODE);
      assert s2cCip != null;

      session.setS2cCipher(s2cCip);
      session.setS2cCipherSize(cf.getIvSize());

      // client to server cipher
      cf = CipherFactory.fromName(kp.get(KexParam.ENCRYPTION_C2S));
      assert cf != null;
      e_c2s = hashKey(e_c2s, cf.getBlkSize(), k);
      Cipher c2sCip = cf.create(e_c2s, iv_c2s, Cipher.DECRYPT_MODE);
      assert c2sCip != null;

      session.setC2sCipher(c2sCip);
      session.setC2sCipherSize(cf.getIvSize());

      // server to client MAC
      MacFactory mf;
      mf = MacFactory.fromName(kp.get(KexParam.MAC_S2C));
      assert mf != null;
      Mac s2cMac = mf.create(mac_s2c);
      assert s2cMac != null;

      session.setS2cMac(s2cMac);
      session.setS2cMacSize(mf.getBlkSize());

      // client to server MAC
      mf = MacFactory.fromName(kp.get(KexParam.MAC_C2S));
      assert mf != null;
      Mac c2sMac = mf.create(mac_c2s);
      assert c2sMac != null;

      session.setC2sMac(c2sMac);
      session.setC2sMacSize(mf.getBlkSize());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private byte[] hashKey(byte[] e, int blockSize, byte[] k) {
    for (ByteBuf b = Unpooled.buffer(); e.length < blockSize; b.clear()) {
      SshByteBufUtil.writeMpInt(b, k);
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