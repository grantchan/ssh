package io.github.grantchan.sshengine.common;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.common.userauth.service.ServiceFactories;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public abstract class AbstractSession extends AbstractLogger
                              implements UsernameHolder {

  /** the network connection between client and server */
  protected Channel channel;

  private final static Set<AbstractSession> sessions = new CopyOnWriteArraySet<>();
  private final static ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();

  static {
    timer.scheduleAtFixedRate(() -> {
      for (AbstractSession s : sessions) {
        s.checkTimeout();
      }
    }, 1, 1, TimeUnit.SECONDS);
  }

  /** the id represents this session */
  private byte[] rawId;

  /*
   * RFC 4253:
   * Both the 'protoversion' and 'softwareversion' strings MUST consist of
   * printable US-ASCII characters, with the exception of whitespace
   * characters and the minus sign (-).
   */
  /** client identification */
  private String clientId = null;
  /** server identification */
  private String serverId = null;

  /** the payload of the client's SSH_MSG_KEXINIT */
  private byte[] rawC2sKex = null;
  /** the payload of the server's SSH_MSG_KEXINIT*/
  private byte[] rawS2cKex = null;

  private List<String> kexInit;

  /*
   * Cipher - algorithm to perform encryption & decryption
   */
  /** Cipher for packet from client to server */
  private Cipher c2sCipher;
  /** Cipher for packet from server to client */
  private Cipher s2cCipher;

  /** Cipher initial vector size for packet from client to server */
  private int c2sCipherSize = 8;
  /** Cipher initial vector size for packet from server to client */
  private int s2cCipherSize = 8;

  /*
   * MAC - Message authentication code, a piece of information used to authenticate a message
   */
  /** Mac for packet from client to server */
  private Mac c2sMac;
  /** Mac for packet from server to client */
  private Mac s2cMac;

  /** Block size of MAC for packet from client to server */
  private int c2sMacSize = 0;
  /** Block size of MAC for packet from server to client */
  private int s2cMacSize = 0;
  /** Default block size of MAC for packet from client to server */
  private int c2sDefMacSize = 0;
  /** Default block size of MAC for packet from server to client */
  private int s2cDefMacSize = 0;

  /*
   * Compression - data compression, to encode the packet using fewer bits than the original
   * representation
   */
  /** Compression algorithm for packet from client to server */
  private Compression c2sCompression;
  /** Compression algorithm for packet from server to client */
  private Compression s2cCompression;

  private Service service;
  private String username;
  private String remoteAddr;

  private long authStartTime = System.currentTimeMillis();
  private volatile boolean isAuthed = false;

  /**
   *  The active state of this session to indicate connection status.
   *  When the connection is established, it's true; when disconnected, false.
   */
  private volatile boolean isActive = false;

  // constructor
  public AbstractSession(Channel channel) {
    this.channel = channel;
    sessions.add(this);
  }

  public byte[] getRawId() {
    return rawId;
  }

  public void setRawId(byte[] rawId) {
    this.rawId = rawId;
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

  public byte[] getRawC2sKex() {
    return rawC2sKex;
  }

  public void setRawC2sKex(byte[] rawC2sKex) {
    this.rawC2sKex = rawC2sKex;
  }

  public byte[] getRawS2cKex() {
    return rawS2cKex;
  }

  public void setRawS2cKex(byte[] rawS2cKex) {
    this.rawS2cKex = rawS2cKex;
  }

  public List<String> getKexInit() {
    return kexInit;
  }

  public void setKexInit(List<String> kexInit) {
    this.kexInit = kexInit;
  }

  /*
   * Cipher
   */
  // Cipher from client to server
  /** Returns the cipher object used for packet comes from client to server */
  public Cipher getC2sCipher() {
    return c2sCipher;
  }
  /** Replaces the cipher object used for packet comes from client to server */
  public void setC2sCipher(Cipher c2sCipher) {
    this.c2sCipher = c2sCipher;
  }

  // Cipher from server to client
  /** Returns the cipher object used for packet comes from server to client */
  public Cipher getS2cCipher() {
    return s2cCipher;
  }
  /** Replaces the cipher object used for packet comes from server to client */
  public void setS2cCipher(Cipher s2cCipher) {
    this.s2cCipher = s2cCipher;
  }

  // Size of the cipher initial vector from client to server
  /** Returns the size of initial vector of the cipher from client to server */
  public int getC2sCipherSize() {
    return c2sCipherSize;
  }
  /** Replaces the size of initial vector of the cipher from client to server */
  public void setC2sCipherSize(int c2sCipherSize) {
    this.c2sCipherSize = c2sCipherSize;
  }

  // Size of the cipher initial vector from server to client
  /** Returns the size of initial vector of the cipher from server to client */
  public int getS2cCipherSize() {
    return s2cCipherSize;
  }
  /** Replaces the size of initial vector of the cipher from server to client */
  public void setS2cCipherSize(int s2cCipherSize) {
    this.s2cCipherSize = s2cCipherSize;
  }

  /*
   * MAC
   */
  // MAC from client to server
  /** Returns the MAC object, which is used for authenticating packet from client to server */
  public Mac getC2sMac() {
    return c2sMac;
  }
  /** Replaces the MAC object, which is used for authenticating packet from client to server */
  public void setC2sMac(Mac c2sMac) {
    this.c2sMac = c2sMac;
  }

  // MAC from server to client
  /** Returns the MAC object, which is used for authenticating packet from server to client */
  public Mac getS2cMac() {
    return s2cMac;
  }
  /** Replaces the MAC object, which is used for authenticating packet from server to client */
  public void setS2cMac(Mac s2cMac) {
    this.s2cMac = s2cMac;
  }

  // Size of the MAC's block from client to server
  /** Returns the block size of the MAC for packet from client to server */
  public int getC2sMacSize() {
    return c2sMacSize;
  }
  /** Replaces the block size of the MAC for packet from client to server */
  public void setC2sMacSize(int c2sMacSize) {
    this.c2sMacSize = c2sMacSize;
  }

  // Size of the MAC's block from server to client
  /** Returns the block size of the MAC for packet from server to client */
  public int getS2cMacSize() {
    return s2cMacSize;
  }
  /** Replaces the block size of the MAC for packet from server to client */
  public void setS2cMacSize(int s2cMacSize) {
    this.s2cMacSize = s2cMacSize;
  }

  // Default size of the MAC's block from client to server
  /** Returns the default block size of the MAC for packet from client to server */
  public int getC2sDefMacSize() {
    return c2sDefMacSize;
  }
  /** Replaces the default block size of the MAC for packet from client to server */
  public void setC2sDefMacSize(int c2sDefMacSize) {
    this.c2sDefMacSize = c2sDefMacSize;
  }

  // Default size of the MAC's block from server to client
  /** Returns the default block size of the MAC for packet from server to client */
  public int getS2cDefMacSize() {
    return s2cDefMacSize;
  }
  /** Replaces the default block size of the MAC for packet from server to client */
  public void setS2cDefMacSize(int s2cDefMacSize) {
    this.s2cDefMacSize = s2cDefMacSize;
  }

  /*
   * Compression
   */
  // Compression from client to server
  /** Returns the compression object for packet packet from client to server */
  public Compression getC2sCompression() {
    return c2sCompression;
  }
  /** Replaces the compression object for packet packet from client to server */
  public void setC2sCompression(Compression c2sCompression) {
    this.c2sCompression = c2sCompression;
  }

  // Compression from server to client
  /** Returns the compression object for packet packet from server to client */
  public Compression getS2cCompression() {
    return s2cCompression;
  }
  /** Replaces the compression object for packet packet from server to client */
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

  /** Returns the connection state of this session, when connected, true; otherwise, false. */
  public boolean isActive() {
    return isActive;
  }

  /** Sets the active state of the connection within this session */
  public void setActive(boolean isActive) {
    this.isActive = isActive;
  }

  public void sendKexInit(byte[] payload) {
    ByteBuf buf = createMessage(SshMessage.SSH_MSG_KEXINIT);

    buf.writeBytes(payload);

    channel.writeAndFlush(buf);
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

    channel.writeAndFlush(buf);
  }

  /**
   * Obtains the remote ip address where this channel is connected to.
   */
  private String getRemoteAddress() {
    if (remoteAddr == null) {
      SocketAddress sa = channel.remoteAddress();
      if (sa instanceof InetSocketAddress) {
        InetSocketAddress isa = (InetSocketAddress) sa;

        remoteAddr = isa.getAddress().getHostAddress();
      } else {
        remoteAddr = sa.toString();
      }
    }
    return remoteAddr;
  }

  private void checkTimeout() {
/*
    long authElapsed = System.currentTimeMillis() - authStartTime;
    if (isActive && !isAuthed && authElapsed > 5000) {
      logger.debug("[{}] Timeout - reason: Authentication process timeout since it's taken {} ms",
          this, authElapsed);

      notifyDisconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR, "Authentication timeout");

      disconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR, "Authentication timeout");
    }
*/
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

    channel.writeAndFlush(pg);
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

    channel.writeAndFlush(newKeys);
  }

  public void replyChannelSuccess(int channelId) {
    ByteBuf cs = createMessage(SshMessage.SSH_MSG_CHANNEL_SUCCESS);

    cs.writeInt(channelId);

    logger.debug("[{}] Replying SSH_MSG_CHANNEL_SUCCESS... channel rawId:{}", this, channelId);

    channel.writeAndFlush(cs);
  }

  public void replyChannelFailure(int channelId) {
    ByteBuf cs = createMessage(SshMessage.SSH_MSG_CHANNEL_FAILURE);

    cs.writeInt(channelId);

    logger.debug("[{}] Replying SSH_MSG_CHANNEL_FAILURE... channel rawId:{}", this, channelId);

    channel.writeAndFlush(cs);
  }

  /**
   * Creates a {@link ByteBuf} object - netty data container, whose length is 256 bytes.
   *
   * <p>
   *   Internally, it calls the {@link #createBuffer(int)} with parameter 256 bytes.
   * </p>
   *
   * @return a newly created {@link ByteBuf} object
   *
   * @see #createBuffer(int)
   */
  public ByteBuf createBuffer() {
    return createBuffer(256);
  }

  /**
   * Creates a {@link ByteBuf} object - netty data container, with the given size.
   *
   * @param size size of the buffer to create
   * @return a newly created {@link ByteBuf} object
   *
   * @see #createBuffer()
   */
  public ByteBuf createBuffer(int size) {
    return channel.alloc().buffer(size);
  }

  /**
   * Creates a {@link ByteBuf} object to represent a SSH message.
   */
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

    channel.close()
           .addListener(f -> {
             if (f.isSuccess()) {
               setActive(false);
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
