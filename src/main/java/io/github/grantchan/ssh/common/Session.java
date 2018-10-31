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
   * <p>This message causes immediate termination of the connection. All implementations MUST be
   * able to process this message; they SHOULD be able to send this message.</p>
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
   * Sends the {@link SshMessage#SSH_MSG_SERVICE_ACCEPT} message to the client to notify the client
   * the service can be supported, and permits to use.
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

    return remoteAddr.getAddress().getHostAddress();
  }

  /**
   * Sends the {@link SshMessage#SSH_MSG_KEX_DH_GEX_GROUP} message to the client, along with p and g
   *
   * @param p  safe prime
   * @param g  generator for subgroup in GF(p)
   *
   * @see <a href="https://tools.ietf.org/html/rfc4419#section-3">Diffie-Hellman Group and Key Exchange</a>
   */
  public void replyDhGexGroup(BigInteger p, BigInteger g) {
    ByteBuf pg = createMessage(SshMessage.SSH_MSG_KEX_DH_GEX_GROUP);

    SshIoUtil.writeMpInt(pg, p);
    SshIoUtil.writeMpInt(pg, g);

    logger.debug("Replying SSH_MSG_KEX_DH_GEX_GROUP...");
    ctx.channel().writeAndFlush(pg);
  }

  /**
   * Sends the {@link SshMessage#SSH_MSG_NEWKEYS} message to the client to notify the key exchange
   * process ends.
   *
   * <p>This message is sent with the old keys and algorithms.  All messages sent after this message
   * MUST use the new keys and algorithms.</p>
   *
   * <p>When this message is received, the new keys and algorithms MUST be used for receiving.</p>
   *
   * <p>The purpose of this message is to ensure that a party is able to respond with an
   * {@link SshMessage#SSH_MSG_DISCONNECT} message that the other party can understand if something
   * goes wrong with the key exchange.</p>
   *
   * @see <a href="https://tools.ietf.org/html/rfc4253#section-7.3">Taking Keys Into Use</a>
   */
  public void requestKexNewKeys() {
    ByteBuf newKeys = createMessage(SshMessage.SSH_MSG_NEWKEYS);

    logger.debug("Requesting SSH_MSG_NEWKEYS...");
    ctx.channel().writeAndFlush(newKeys);
  }

  public ByteBuf createBuffer() {
    return ctx.alloc().buffer();
  }

  private ByteBuf createMessage(byte messageId) {
    ByteBuf msg = ctx.alloc().buffer();

    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(messageId);

    return msg;
  }

  /**
   * Sends the {@link SshMessage#SSH_MSG_USERAUTH_SUCCESS} message to client to notify the
   * authentication request is accepted.
   *
   * <p>Note that this is not sent after each step in a multi-method authentication sequence, but
   * only when the authentication is complete.</p>
   *
   * <p>The client MAY send several authentication requests without waiting for responses from
   * previous requests. The server MUST process each request completely and acknowledge any failed
   * requests with a {@link SshMessage#SSH_MSG_USERAUTH_FAILURE} message before processing the next
   * request.</p>
   *
   * <p>A request that requires further messages to be exchanged will be aborted by a subsequent
   * request. A client MUST NOT send a subsequent request if it has not received a response from
   * the server for a previous request. A {@link SshMessage#SSH_MSG_USERAUTH_FAILURE} message MUST
   * NOT be sent for an aborted method.</p>
   *
   * <p>{@link SshMessage#SSH_MSG_USERAUTH_SUCCESS} MUST be sent only once. When
   * {@link SshMessage#SSH_MSG_USERAUTH_SUCCESS} has been sent, any further authentication requests
   * received after that SHOULD be silently ignored.</p>
   *
   * <p>Any non-authentication messages sent by the client after the request that resulted in
   * {@link SshMessage#SSH_MSG_USERAUTH_SUCCESS} being sent MUST be passed to the service being run
   * on top of this protocol. Such messages can be identified by their message numbers
   * (see Section 6).</p>
   *
   * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.1">Responses to Authentication Requests</a>
   */
  public void replyUserAuthSuccess() {
    ByteBuf uas = createMessage(SshMessage.SSH_MSG_USERAUTH_SUCCESS);

    logger.debug("Replying SSH_MSG_USERAUTH_SUCCESS...");
    ctx.channel().writeAndFlush(uas);
  }

  /**
   * Sends the SSH_MSG_USERAUTH_FAILURE message to client to reject the authentication request.
   *
   * <p>It is RECOMMENDED that servers only include those 'method name' values
   * in the name-list that are actually useful. However, it is not illegal to
   * include 'method name' values that cannot be used to authenticate the
   * user.</p>
   * <p>Already successfully completed authentications SHOULD NOT be included in
   * the name-list, unless they should be performed again for some reason.</p>
   *
   * @param remainMethods   a comma-separated name-list of authentication 'method name' values that
   *                        may productively continue the authentication dialog.
   * @param partialSuccess  MUST be {@code true} if the authentication request to which this is a
   *                        response was successful. It MUST be {@code FALSE} if the request was not
   *                        successfully processed.
   * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.1">Responses to Authentication Requests</a>
   */
  public void replyUserAuthFailure(String remainMethods, boolean partialSuccess) {
    ByteBuf uaf = createMessage(SshMessage.SSH_MSG_USERAUTH_FAILURE);

    SshIoUtil.writeUtf8(uaf, remainMethods);
    uaf.writeBoolean(partialSuccess);

    logger.debug("Replying SSH_MSG_USERAUTH_FAILURE...");
    ctx.channel().writeAndFlush(uaf);
  }

  /**
   * Sends the {@link SshMessage#SSH_MSG_KEX_DH_GEX_REPLY} to client. This is the message of step 4
   * in diffie-hellman group key exchange.
   *
   * @param k_s     server public host key and certificates (K_S)
   * @param f       f = g^y mod p, where y is a random number generated by server, 0 < y < (p-1)/2
   * @param sigH    signature of H
   *
   * @see <a href="https://tools.ietf.org/html/rfc4419#section-3">Diffie-Hellman Group and Key Exchange</a>
   */
  public void replyKexDhGexReply(byte[] k_s, byte[] f, byte[] sigH) {
    ByteBuf reply = createMessage(SshMessage.SSH_MSG_KEX_DH_GEX_REPLY);

    SshIoUtil.writeBytes(reply, k_s);
    SshIoUtil.writeBytes(reply, f);
    SshIoUtil.writeBytes(reply, sigH);

    logger.debug("Replying SSH_MSG_KEX_DH_GEX_REPLY...");
    ctx.channel().writeAndFlush(reply);
  }

  public void handleDisconnect(int code, String msg) {
    logger.info("Disconnecting... reason: {}, msg: {}", SshMessage.disconnectReason(code), msg);

    ctx.channel().close();
  }
}
