package io.github.grantchan.sshengine.server.transport.kex;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.kex.DH;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

public class ServerDhGroupEx extends AbstractLogger
                             implements KexGroup {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final MessageDigest md;
  protected Kex kex;
  protected final ServerSession session;

  private int min; // minimal size in bits of an acceptable group
  private int n;   // preferred size in bits of the group the server will send
  private int max; // maximal size in bits of an acceptable group

  private byte expect = SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST;

  public ServerDhGroupEx(MessageDigest md, ServerSession session) {
    this.md = md;
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
  public void handle(int cmd, ByteBuf msg) throws SignatureException, SshException {
    logger.debug("{} Handling key exchange message - {} ...", session, SshMessage.from(cmd));

    if (cmd == SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST_OLD &&
        expect == SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST) {
      handleDhGexRequestOld(msg);

      expect = SshMessage.SSH_MSG_KEX_DH_GEX_INIT;
    } else if (cmd == SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST &&
        expect == SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST) {
      handleDhGexRequest(msg);

      expect = SshMessage.SSH_MSG_KEX_DH_GEX_INIT;
    } else if (cmd == SshMessage.SSH_MSG_KEX_DH_GEX_INIT && cmd == expect) {
      handleDhGexInit(msg);

      expect = SshMessage.SSH_MSG_NEWKEYS;
    } else {
      throw new SshException(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
          "Invalid key exchange message, expect: " + SshMessage.from(expect) + ", actual: " +
              SshMessage.from(cmd));
    }
  }

  private void handleDhGexRequestOld(ByteBuf msg) throws SshException {
    /*
     * RFC 4419:
     * The client sends SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
     *   byte     SSH_MSG_KEX_DH_GEX_REQUEST_OLD
     *   uint32   n, preferred size in bits of the group the server will send
     */
    n = msg.readInt();
    min = -1;
    max = -1;

    DH dh = getDH(min, n, max);
    this.kex = dh;

    /*
     * RFC 4419:
     * The server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     *   byte     SSH_MSG_KEX_DH_GEX_GROUP
     *   mpint    p, safe prime
     *   mpint    g, generator for subgroup in GF(p)
     */
    session.replyDhGexGroup(dh.getP(), dh.getG());
  }

  private void handleDhGexRequest(ByteBuf msg) throws SshException {
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

    DH dh = getDH(min, n, max);
    this.kex = dh;

    /*
     * RFC 4419:
     * The server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     *   byte     SSH_MSG_KEX_DH_GEX_GROUP
     *   mpint    p, safe prime
     *   mpint    g, generator for subgroup in GF(p)
     */
    session.replyDhGexGroup(dh.getP(), dh.getG());
  }

  private DH getDH(int min, int n, int max) throws SshException {
    BigInteger p;
    if (n == 2048) {
      p = new BigInteger("CF14CEC123C83DF3CF6EA7A5A4C03FB0B1542DCAA09DDFC11B5F8AD4468D28A1" +
                         "93BC550E267308712F30688BB9559F68224F1262331E900F9F89E04A7CE2A012" +
                         "6FB2B69008B71219ED6109E6E353A893977179CD9CC15C980D8921EA61C56FD3" +
                         "6752819816E7D658F22F2FC1698C30392E4BB97023B0D9943B13286CAC1C351C" +
                         "342341CCE3234D8C5C70B6369158D6DEA23037045D19C690FAF4A7F50750A2EC" +
                         "EF42223DA315999847C624A5BCAA0CF634F0F827DC14762E4F63827A15411BC8" +
                         "CFF3BCAAFD3C5D69D9D033B5D99FEF178881960E09C085819EF2255BD0715378" +
                         "E051EA56AB9341F46698FAF86B736C745E1B152082251CBB6969E8F12F909B43", 16);
    } else if (n == 4096) {
      p = new BigInteger("C082C6D5214016F2748DBC7D756DF9A769F0FCA6A162ACAF8DF354C82684FA5D" +
                         "6471B940AB4283F6BF477624A7A880AE06B1AB60E0EA339B0875244F28869D56" +
                         "61A0DC75425A889F6BD03E937983F896DB02E3E5D782F68B7463E88DEC396ED8" +
                         "C03F7F832DD1D1056EAC8444AEB64C73DB754BAAFCB4CBD642CD5C6257794434" +
                         "494E8A2DFBA7EAA108935B4045CB49EE0E6A2EB6E75E72CFF6B9B7BE69A61D44" +
                         "511EE6CA207C43012CE8DA86C293AD25FE9B3610806DF16CEE48537784CCF04C" +
                         "2A3AA5F1CE5CA302E3D5B07B925B32910A72CCDAC361582836287AF4E7D20A0C" +
                         "314EC58292EDC1C67E9DEE7FC0A88A1ADCE1C6EC45D2398E523858892086888B" +
                         "60E12CD3374A454BF59890A98B4D7A784B64D809CB59207CF9360193C920896F" +
                         "731DA355CABDFCBDF827EFB03D300D94AB207C52B00E78146680A793F3EA65D4" +
                         "428F1BC2456AACDC99985DB10934182F431195FB517DC37F643360EC34859E86" +
                         "D49602E1A2454204982F4AECBC4C7411322E4FCD4AE8EE5076B0D4707E61878E" +
                         "F568FE50AC8B4786DDC2AD7391B8FA9D23651A5D695DF30A4C29CEFB57ABC21D" +
                         "E062D4C16E345AB416CCF69B3AA2C8076BD7730DDD2AF3249D7AA5D0613439F3" +
                         "8DC97536758BF31687122B6D5FC32AEA7E306020A5DA4CBC719F9BFCB1E17EE1" +
                         "968D21ECCBAAB24923B7D7FFF30714C4713472C0BBF4D846D39E0215C8915583", 16);
    } else if (n == 8192) {
      p = new BigInteger("D3584411656A5311623FF0D234C21F198B128AE78662AB22596F7FDB40C94939" +
                         "4BF6CEDA3209BEA8F64DB8F6A39F3DCAA89D3EEA0821F7DA8938F20089CA1C80" +
                         "67BA93163268C7CAE191760CCF8B5FDC0E4168B9986E32CC396B17F69A9EF032" +
                         "BA06AB969DFF1BDA3B8F5A6A8A0592AAEC5B5BB1A604A8C0589DC7DE99C87E99" +
                         "2BE1A2F74D817AD5424E8AE14808F09213B1C268A47196E5013D75CAA5F8C76B" +
                         "6B5A951D48D0F8E066360E409D6076D99A3AF7CAB631041B6DD14BBF9C0E0BC3" +
                         "9B66542C9D3C7E98C97E3A1C08C25047963D6F5A0D05EB3684B3B5B31379838B" +
                         "1AE1D05677898A3FC986F2D01CD44A25D46AD8D9626774DD8AFE4723987E7B87" +
                         "AFCD1560FA3931A760C8E96C58552A1B6953441F52F4F8A49C0597C9F79B24D9" +
                         "650C4C901A4E862458F6CF8451D445A1A9330C65A0CD00C9254A419BBF72B4C6" +
                         "6459B4E50CC2849782FFA6D3C9EEDFE7F7983E94A0499F8AC90F41081BB6756D" +
                         "22713A4D4FC61784410192827AC6ECB043870E593EB71EEDA34BAEC1CCBFB94E" +
                         "746367E19732FCAA22AB9736093BE512D38C293C77C175B977B0590C4D72D8CC" +
                         "D8CC962A77C9AEA280B43BBB7669447AF02539857442AE168E77560184CDCC49" +
                         "5D99DECEAE61A72129A44A0A5AE9D7779B157C7F262AF465D2F6DFFD937ED535" +
                         "E6CAF2AF9C9FEC8C499EF734FAE66A075EA63B8DC37C0A8F1E07031C3D9EADA1" +
                         "0D3E7ED2B7487A9E35DD5A14A147351BC5AB87AAC28D76B3CEA7CC2EF8C3F783" +
                         "A325C5926E48839087E123CA096623C77ACCD0509D38849D3C3AAF499905065E" +
                         "87F64B5BC390D9763E5FF00B80432C0747AC6753B9439ED5476C486A6B44A2A9" +
                         "33533198700168A49C6020BC4ACDC1513604B8EAE7B7920DF6C4A963E93CEB05" +
                         "4D5380689DA6F81E0A084C499F28D7623F9634AE2C3FF00CC267DAB9A84EB81F" +
                         "54470923C64852CCD7B39178BF750E9268780F317D0C6F059A401F880CEC81F8" +
                         "E7C502082824E0F7F0673B137DAEE72DB42BD6B72946905E0D0870B1055F0F95" +
                         "14FD85E0C05BA82C7244FA88CD5BFD7EF64A7C29385CE17744C2B8367EB1A9B1" +
                         "95492B0B14A2BBC640872890B717F8B13F6AAAB8215721723C8CE036019163F5" +
                         "222CBAFF5DE69D4004545A60207248208C67B5C9E097B2B9EB61CA61E205E8F0" +
                         "3AB13F08AB7C85A1BC90E143E82879E39280D825BBA3E5B3E4F61810D6760D70" +
                         "2D97EECCDFE68F5643D0263C38D213986082EF1113508C42AE38F29F8E7A80EF" +
                         "785A6C57F9CE8D1F884C63A2551AE2AD80DB3A372D169596ADBFCD27BD44D127" +
                         "CAE086706842FB4F52420D10CD08D472AEDC5B98CD788BCB63D0CE9B04715B35" +
                         "5B622D69AD1F5C1215DEE5B0EB8CB47A27A88ED10C5CEF6B462A65F701AF0AD8" +
                         "28D41932E23D3E1D7A86083E3554F092D8EF81454B7B60BE78B129011D3EC8CB", 16);
    } else {
      throw new IllegalArgumentException();
    }
    BigInteger g = new BigInteger("2", 16);

    return new DH(p, g);
  }

  private void handleDhGexInit(ByteBuf req) throws SignatureException, SshException {
    /*
     * RFC 4419:
     * The client sends SSH_MSG_KEX_DH_GEX_INIT
     *   byte    SSH_MSG_KEX_DH_GEX_INIT
     *   mpint   e
     */
    BigInteger e = ByteBufIo.readMpInt(req);
    kex.receivedPubKey(e);

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

    byte[] h_s = Bytes.concat(
        Bytes.joinWithLength(v_c, v_s),
        Bytes.joinWithLength(i_c, i_s, k_s)
    );

    if (min == -1 || max == -1) { // old request
      h_s = Bytes.concat(h_s, Bytes.fromInt(n));
    } else {
      byte[] joined = new byte[3 * Integer.BYTES];

      int off = 0;
      for (int i : Arrays.asList(min, n, max)) {
        System.arraycopy(Bytes.fromInt(i), 0, joined, off, Integer.BYTES);
        off += Integer.BYTES;
      }

      h_s = Bytes.concat(h_s, joined);
    }

    h_s = Bytes.concat(
        h_s,
        Bytes.joinWithLength(((DH)kex).getP(), ((DH)kex).getG(), kex.getReceivedPubKey(),
            kex.getPubKey(), kex.getSecretKey())
    );

    md.update(h_s, 0, h_s.length);
    byte[] h = md.digest();
    session.setRawId(h);

    List<String> kexParams = session.getKexInit();

    Signature sig = SignatureFactories.create(kexParams.get(KexProposal.Param.SERVER_HOST_KEY),
                                              kp.getPrivate());
    if (sig == null) {
      throw new IllegalArgumentException("Unknown signature: " +
          kexParams.get(KexProposal.Param.SERVER_HOST_KEY));
    }

    sig.update(h);

    byte[] sigH = Bytes.concat(
          Bytes.addLen(kexParams.get(KexProposal.Param.SERVER_HOST_KEY)),
          Bytes.addLen(sig.sign())
        );

    session.replyKexDhGexReply(k_s, kex.getPubKey(), sigH);

    logger.debug("{} KEX process completed after SSH_MSG_KEX_DH_GEX_INIT", session);

    session.requestKexNewKeys();
  }
}
