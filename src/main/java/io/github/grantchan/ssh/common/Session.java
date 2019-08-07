package io.github.grantchan.ssh.common;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.transport.compression.Compression;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.github.grantchan.ssh.common.userauth.service.ServiceFactories;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public abstract class Session implements IdHolder, UsernameHolder {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  protected ChannelHandlerContext ctx;

  private final static Set<Session> sessions = new CopyOnWriteArraySet<>();
  private final static ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();

  static {
    timer.scheduleAtFixedRate(() -> {
      for (Session s : sessions) {
        s.checkTimeout();
      }
    }, 1, 1, TimeUnit.SECONDS);
  }

  private byte[] id;

  /*
   * RFC 4253:
   * Both the 'protoversion' and 'softwareversion' strings MUST consist of
   * printable US-ASCII characters, with the exception of whitespace
   * characters and the minus sign (-).
   */
  private String clientId = null;  // client identification
  private String serverId = null;  // server identification

  private byte[] c2sKex = null; // the payload of the client's SSH_MSG_KEXINIT
  private byte[] s2cKex = null; // the payload of the server's SSH_MSG_KEXINIT
  private List<String> kexInit;

  private Cipher c2sCipher, s2cCipher;
  private int c2sCipherSize = 8, s2cCipherSize = 8;

  private Mac c2sMac, s2cMac;
  private int c2sMacSize = 0, s2cMacSize = 0;
  private int c2sDefMacSize = 0, s2cDefMacSize = 0;

  private Compression c2sCompression, s2cCompression;

  private Service service;
  private String username;
  private String remoteAddr;

  private long authStartTime = System.currentTimeMillis();
  private volatile boolean isAuthed = false;
  private volatile boolean isActive = false;

  // constructor
  public Session(ChannelHandlerContext ctx) {
    this.ctx = ctx;
    sessions.add(this);
  }

  @Override
  public byte[] getId() {
    return id;
  }

  public void setId(byte[] id) {
    this.id = id;
  }

  @Override
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }


  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getServerId() {
    return serverId;
  }

  public void setServerId(String serverId) {
    this.serverId = serverId;
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

  public void setKexInit(List<String> kexInit) {
    this.kexInit = kexInit;
  }

  public List<String> getKexInit() {
    return kexInit;
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

  public Compression getC2sCompression() {
    return c2sCompression;
  }

  public void setC2sCompression(Compression c2sCompression) {
    this.c2sCompression = c2sCompression;
  }

  public Compression getS2cCompression() {
    return s2cCompression;
  }

  public void setS2cCompression(Compression s2cCompression) {
    this.s2cCompression = s2cCompression;
  }

  public boolean isAuthed() {
    return isAuthed;
  }

  public void setAuthed(boolean authed) {
    if (!isAuthed && authed) {
      logger.debug("[{}] Authentication process completed in {} ms", this,
          System.currentTimeMillis() - authStartTime);
    }
    this.isAuthed = authed;
  }

  public void setActive(boolean isActive) {
    this.isActive = isActive;
  }

  public void sendKexInit(byte[] payload) {
    ByteBuf buf = createMessage(SshMessage.SSH_MSG_KEXINIT);

    buf.writeBytes(payload);

    ctx.channel().writeAndFlush(buf);
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
  public void notifyDisconnect(int reason, String message) {
    ByteBuf buf = createMessage(SshMessage.SSH_MSG_DISCONNECT);

    buf.writeInt(reason);
    ByteBufIo.writeUtf8(buf, message);
    ByteBufIo.writeUtf8(buf, "");

    ctx.channel().writeAndFlush(buf);
  }

  private String getRemoteAddress() {
    if (remoteAddr == null) {
      InetSocketAddress isa = (InetSocketAddress) ctx.channel().remoteAddress();

      remoteAddr = isa.getAddress().getHostAddress();
    }
    return remoteAddr;
  }

  private void checkTimeout() {
    long authElapsed = System.currentTimeMillis() - authStartTime;
    if (isActive && !isAuthed && authElapsed > 5000) {
      logger.debug("[{}] Timeout - reason: Authentication process timeout since it's taken {} ms",
          this, authElapsed);

      notifyDisconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR, "Authentication timeout");

      disconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR, "Authentication timeout");
    }
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

    ByteBufIo.writeMpInt(pg, p);
    ByteBufIo.writeMpInt(pg, g);

    logger.debug("[{}] Replying SSH_MSG_KEX_DH_GEX_GROUP...", this);

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

    logger.debug("[{}] Requesting SSH_MSG_NEWKEYS...", this);

    ctx.channel().writeAndFlush(newKeys);
  }

  public ByteBuf createBuffer() {
    return ctx.alloc().buffer();
  }

  protected ByteBuf createMessage(byte messageId) {
    ByteBuf msg = createBuffer();

    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(messageId);

    return msg;
  }

  /**
   * Print a log information regarding the disconnect reason, disconnect the network channel
   *
   * @param code  the disconnect reason code
   * @param msg   message about the reason
   */
  public void disconnect(int code, String msg) {
    logger.info("[{}] Disconnecting... reason: {}, msg: {}",
        this, SshMessage.disconnectReason(code), msg);

    ctx.channel().close()
       .addListener(f -> {
         if (f.isSuccess()) {
           isActive = false;
         }
       });
  }

  /**
   * Create a {@link Service} instance by a given name
   * @param name          name of the service to create
   * @throws SshException  if the given name of service is not supported
   */
  public void acceptService(String name) throws SshException {
    service = ServiceFactories.create(name, this);
    if (service == null) {
      logger.info("Requested service ({}) from {} is unavailable, rejected.",
          name, getRemoteAddress());

      throw new SshException(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
          "Bad service requested - '" + name + "'");
    }
  }

  public Service getService() {
    return this.service;
  }

  @Override
  public String toString() {
    return getUsername() + "@" + getRemoteAddress();
  }
}
