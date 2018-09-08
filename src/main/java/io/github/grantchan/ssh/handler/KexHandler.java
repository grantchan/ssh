package io.github.grantchan.ssh.handler;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.kex.CipherFactory;
import io.github.grantchan.ssh.kex.DHSpec;
import io.github.grantchan.ssh.kex.MacFactory;
import io.github.grantchan.ssh.kex.SignatureFactory;
import io.github.grantchan.ssh.util.SshByteBufUtil;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static io.github.grantchan.ssh.common.SshConstant.*;

public class KexHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private byte[] clientKexInit = null; // the payload of the client's SSH_MSG_KEXINIT

  private List<String> kexInit = null;
  private int n, min, max;

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    ByteBuf req = (ByteBuf) msg;

    int cmd = req.readByte() & 0xFF;
    switch (cmd) {
      case SSH_MSG_KEXINIT:
        handleKexInit(ctx, req);
        break;

      case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
        handleKexDhGexRequestOld(ctx, req);
        break;

      case SSH_MSG_KEX_DH_GEX_REQUEST:
        handleKexDhGexRequest(ctx, req);
        break;
    }
  }

  protected void handleKexInit(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * the client sends SSH_MSG_KEXINIT:
     * byte         SSH_MSG_KEXINIT
     * byte[16]     cookie (random bytes)
     * name-list    kex_algorithms
     * name-list    server_host_key_algorithms
     * name-list    encryption_algorithms_client_to_server
     * name-list    encryption_algorithms_server_to_client
     * name-list    mac_algorithms_client_to_server
     * name-list    mac_algorithms_server_to_client
     * name-list    compression_algorithms_client_to_server
     * name-list    compression_algorithms_server_to_client
     * name-list    languages_client_to_server
     * name-list    languages_server_to_client
     * boolean      first_kex_packet_follows
     * uint32       0 (reserved for future extension)
     */
    int startPos = msg.readerIndex();
    msg.skipBytes(MSG_KEX_COOKIE_SIZE);

    kexInit = resolveKexInit(msg);

    msg.readBoolean();
    msg.readInt();

    int payloadLen = msg.readerIndex() - startPos;
    clientKexInit = new byte[payloadLen + 1];
    clientKexInit[0] = SSH_MSG_KEXINIT;
    msg.getBytes(startPos, clientKexInit, 1, payloadLen);
  }

  private List<String> resolveKexInit(ByteBuf buf) {
    List<String> result = new ArrayList<>(10);

    // kex
    String c2s = SshByteBufUtil.readUtf8(buf);
    String s2c = "diffie-hellman-group-exchange-sha1";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(0, negotiate(c2s, s2c));

    // server host key
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(SignatureFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(1, negotiate(c2s, s2c));

    // encryption c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(CipherFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(2, negotiate(c2s, s2c));

    // encryption s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(CipherFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(3, negotiate(c2s, s2c));

    // mac c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(MacFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(4, negotiate(c2s, s2c));

    // mac s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = NamedObject.getNames(MacFactory.values);
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(5, negotiate(c2s, s2c));

    // compression c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "none";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(6, negotiate(c2s, s2c));

    // compression s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "none";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(7, negotiate(c2s, s2c));

    // language c2s
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(8, negotiate(c2s, s2c));

    // language s2c
    c2s = SshByteBufUtil.readUtf8(buf);
    s2c = "";
    logger.debug("server said: {}", s2c);
    logger.debug("client said: {}", c2s);
    result.add(9, negotiate(c2s, s2c));

    return result;
  }

  private String negotiate(String c2s, String s2c) {
    String[] c = c2s.split(",");
    for (String ci : c) {
      if (s2c.contains(ci)) {
        return ci;
      }
    }
    return null;
  }

  protected void handleKexDhGexRequestOld(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * the client sends SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
     * byte     SSH_MSG_KEX_DH_GEX_REQUEST_OLD
     * uint32   n, preferred size in bits of the group the server will send
     */
    n = msg.readInt();
    min = -1;
    max = -1;

    handleKexDhGexRequest(ctx, min, n, max);
  }

  protected void handleKexDhGexRequest(ChannelHandlerContext ctx, ByteBuf msg) {
    /*
     * the client sends SSH_MSG_KEX_DH_GEX_REQUEST:
     * byte     SSH_MSG_KEX_DH_GEX_REQUEST
     * uint32   min, minimal size in bits of an acceptable group
     * uint32   n,   preferred size in bits of the group the server will send
     * uint32   max, maximal size in bits of an acceptable group
     */
    min = msg.readInt();
    n = msg.readInt();
    max = msg.readInt();

    handleKexDhGexRequest(ctx, min, n, max);
  }

  protected void handleKexDhGexRequest(ChannelHandlerContext ctx, int min, int n, int max) {
    /*
     * the server responds with SSH_MSG_KEX_DH_GEX_GROUP:
     * byte     SSH_MSG_KEX_DH_GEX_GROUP
     * mpint    p, safe prime
     * mpint    g, generator for subgroup in GF(p)
     */
    DHSpec spec = getDH(min, n, max);
    
    ByteBuf pg = ctx.alloc().buffer();
    pg.writerIndex(SSH_PACKET_HEADER_LENGTH);
    pg.readerIndex(SSH_PACKET_HEADER_LENGTH);

    pg.writeByte(SSH_MSG_KEX_DH_GEX_GROUP);

    SshByteBufUtil.writeMpInt(pg, spec.getP());
    SshByteBufUtil.writeMpInt(pg, spec.getG());

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
}
