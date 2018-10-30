package io.github.grantchan.ssh.common;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.List;

public class Session {

  private Logger logger = LoggerFactory.getLogger(getClass());

  private ChannelHandlerContext ctx;

  public Session(ChannelHandlerContext ctx) {
    this.ctx = ctx;
  }

  /*
     * RFC 4253:
     * Both the 'protoversion' and 'softwareversion' strings MUST consist of
     * printable US-ASCII characters, with the exception of whitespace
     * characters and the minus sign (-).
     */
  private       String clientVer = null;            // client identification
  private final String serverVer = "SSH-2.0-DEMO";  // server identification

  private byte[] c2sKex = null; // the payload of the client's SSH_MSG_KEXINIT
  private byte[] s2cKex = null; // the payload of the server's SSH_MSG_KEXINIT
  private List<String> kexParams;

  private Cipher c2sCipher, s2cCipher;
  private int c2sCipherSize = 8, s2cCipherSize = 8;

  private Mac c2sMac, s2cMac;
  private int c2sMacSize = 0, s2cMacSize = 0;
  private int c2sDefMacSize = 0, s2cDefMacSize = 0;

  private String username;

  public String getClientVer() {
    return clientVer;
  }

  public void setClientVer(String clientVer) {
    this.clientVer = clientVer;
  }

  public String getServerVer() {
    return serverVer;
  }

  public byte[] getC2sKex() {
    return c2sKex;
  }

  public void setC2sKex(byte[] c2sKex) {
    this.c2sKex = c2sKex;
  }

  public byte[] getS2cKex() {
    return s2cKex;
  }

  public void setS2cKex(byte[] s2cKex) {
    this.s2cKex = s2cKex;
  }

  public void setKexParams(List<String> kexParams) {
    this.kexParams = kexParams;
  }

  public List<String> getKexParams() {
    return kexParams;
  }

  public Cipher getC2sCipher() {
    return c2sCipher;
  }

  public void setC2sCipher(Cipher c2sCipher) {
    this.c2sCipher = c2sCipher;
  }

  public Cipher getS2cCipher() {
    return s2cCipher;
  }

  public void setS2cCipher(Cipher s2cCipher) {
    this.s2cCipher = s2cCipher;
  }

  public int getC2sCipherSize() {
    return c2sCipherSize;
  }

  public void setC2sCipherSize(int c2sCipherSize) {
    this.c2sCipherSize = c2sCipherSize;
  }

  public int getS2cCipherSize() {
    return s2cCipherSize;
  }

  public void setS2cCipherSize(int s2cCipherSize) {
    this.s2cCipherSize = s2cCipherSize;
  }

  public Mac getC2sMac() {
    return c2sMac;
  }

  public void setC2sMac(Mac c2sMac) {
    this.c2sMac = c2sMac;
  }

  public Mac getS2cMac() {
    return s2cMac;
  }

  public void setS2cMac(Mac s2cMac) {
    this.s2cMac = s2cMac;
  }

  public int getC2sMacSize() {
    return c2sMacSize;
  }

  public void setC2sMacSize(int c2sMacSize) {
    this.c2sMacSize = c2sMacSize;
  }

  public int getS2cMacSize() {
    return s2cMacSize;
  }

  public void setS2cMacSize(int s2cMacSize) {
    this.s2cMacSize = s2cMacSize;
  }

  public int getC2sDefMacSize() {
    return c2sDefMacSize;
  }

  public void setC2sDefMacSize(int c2sDefMacSize) {
    this.c2sDefMacSize = c2sDefMacSize;
  }

  public int getS2cDefMacSize() {
    return s2cDefMacSize;
  }

  public void setS2cDefMacSize(int s2cDefMacSize) {
    this.s2cDefMacSize = s2cDefMacSize;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  /**
   * Sends a disconnection message to terminate the connection.
   * <p>This message causes immediate termination of the connection.  All implementations MUST be able
   * to process this message; they SHOULD be able to send this message.</p>
   *
   * @param reason   the reason code, it gives the reason in a more machine-readable format,
   *                 it should be one of the value in the Disconnection Messages Reason Codes and
   *                 Descriptions section in {@link SshMessage}.
   * @param message  the Disconnection Message, it gives a more specific explanation in a
   *                 human-readable form
   *
   * @see <a href="https://tools.ietf.org/html/rfc4253#section-11.1">Disconnection Message</a>
   */
  public void disconnect(int reason, String message) {
    ByteBuf buf = createMessage(SshMessage.SSH_MSG_DISCONNECT);

    buf.writeInt(reason);
    SshIoUtil.writeUtf8(buf, message);
    SshIoUtil.writeUtf8(buf, "");

    ctx.channel().writeAndFlush(buf).addListener((ChannelFuture f) -> {
      if (f.isDone()) {
        f.channel().close().sync();
      }
    });
  }

  /**
   * By sending a SSH_MSG_SERVICE_ACCEPT message to the client, the server notify the client that
   * the service can be supported, and permits the client to use
   *
   * @param svcName  the service name requested by client
   *
   * @see <a href="https://tools.ietf.org/html/rfc4253#section-10">Service Request</a>
   */
  public void accept(String svcName) {
    ByteBuf buf = createMessage(SshMessage.SSH_MSG_SERVICE_ACCEPT);

    SshIoUtil.writeUtf8(buf, svcName);

    ctx.channel().writeAndFlush(buf);
  }

  public String getRemoteAddress() {
    InetSocketAddress remoteAddr = (InetSocketAddress) ctx.channel().remoteAddress();

    return String.valueOf(remoteAddr.getAddress());
  }

  public void replyDhGexGroup(BigInteger p, BigInteger g) {
    ByteBuf pg = createMessage(SshMessage.SSH_MSG_KEX_DH_GEX_GROUP);

    SshIoUtil.writeMpInt(pg, p);
    SshIoUtil.writeMpInt(pg, g);

    logger.debug("Replying SSH_MSG_KEX_DH_GEX_GROUP...");
    ctx.channel().writeAndFlush(pg);
  }

  public void requestKexNewKeys() {
    ByteBuf newKeys = createMessage(SshMessage.SSH_MSG_NEWKEYS);

    logger.debug("Requesting SSH_MSG_NEWKEYS...");
    ctx.channel().writeAndFlush(newKeys);
  }

  private ByteBuf createMessage(byte messageId) {
    ByteBuf msg = ctx.alloc().buffer();

    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(messageId);

    return msg;
  }
}
