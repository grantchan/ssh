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
  private static final int DEFAULT_BUFFER_SIZE = 256;

  /** the network connection between client and server */
  protected Channel channel;

  private static final Set<AbstractSession> sessions = new CopyOnWriteArraySet<>();
  private static final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();

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
  private int c2sCipherBlkSize = 8;
  /** Cipher initial vector size for packet from server to client */
  private int s2cCipherBlkSize = 8;

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
  protected Cipher getC2sCipher() {
    return c2sCipher;
  }
  /** Replaces the cipher object used for packet comes from client to server */
  protected void setC2sCipher(Cipher c2sCipher) {
    this.c2sCipher = c2sCipher;
  }

  // Cipher from server to client
  /** Returns the cipher object used for packet comes from server to client */
  protected Cipher getS2cCipher() {
    return s2cCipher;
  }
  /** Replaces the cipher object used for packet comes from server to client */
  protected void setS2cCipher(Cipher s2cCipher) {
    this.s2cCipher = s2cCipher;
  }

  /**
   * <p>For caller to obtain the cipher object, it simplifies the function call by abstracting the
   * session type, client or server. The server session should return the C2S cipher, while the
   * client session should return the S2C cipher.</p>
   *
   * @return the cipher object for incoming packet.
   */
  public abstract Cipher getInCipher();

  public abstract void setInCipher(Cipher inCipher);

  /**
   * <p>For caller to obtain the cipher object, it simplifies the function call by abstracting the
   * session type, client or server. The server session should return the S2C cipher, while the
   * client session should return the C2S cipher.</p>
   *
   * @return the cipher object for outgoing packet.
   */
  public abstract Cipher getOutCipher();

  public abstract void setOutCipher(Cipher outCipher);

  // Size of the cipher initial vector from client to server
  /** Returns the size of initial vector of the cipher from client to server */
  protected int getC2sCipherBlkSize() {
    return c2sCipherBlkSize;
  }
  /** Replaces the size of initial vector of the cipher from client to server */
  protected void setC2sCipherBlkSize(int c2sCipherBlkSize) {
    this.c2sCipherBlkSize = c2sCipherBlkSize;
  }

  // Size of the cipher initial vector from server to client
  /** Returns the size of initial vector of the cipher from server to client */
  protected int getS2cCipherBlkSize() {
    return s2cCipherBlkSize;
  }
  /** Replaces the size of initial vector of the cipher from server to client */
  protected void setS2cCipherBlkSize(int s2cCipherBlkSize) {
    this.s2cCipherBlkSize = s2cCipherBlkSize;
  }

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the cipher block size.
   *
   * <p>For server session, it should return the C2S cipher block size, since C2S is the incoming
   * direction, while client session, it should return the S2C cipher block size.</p>
   *
   * @return the block size of the incoming cipher
   */
  public abstract int getInCipherBlkSize();

  public abstract void setInCipherBlkSize(int inCipherBlkSize);

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the cipher block size.
   *
   * <p>For server session, it should return the S2C cipher block size, since S2C is the outgoing
   * direction, while client session, it should return the C2S cipher block size.</p>
   *
   * @return the block size of the outgoing cipher
   */
  public abstract int getOutCipherBlkSize();

  public abstract void setOutCipherBlkSize(int outCipherBlkSize);

  /*
   * MAC
   */
  // MAC from client to server
  /** Returns the MAC object, which is used for authenticating packet from client to server */
  protected Mac getC2sMac() {
    return c2sMac;
  }
  /** Replaces the MAC object, which is used for authenticating packet from client to server */
  protected void setC2sMac(Mac c2sMac) {
    this.c2sMac = c2sMac;
  }

  // MAC from server to client
  /** Returns the MAC object, which is used for authenticating packet from server to client */
  protected Mac getS2cMac() {
    return s2cMac;
  }
  /** Replaces the MAC object, which is used for authenticating packet from server to client */
  protected void setS2cMac(Mac s2cMac) {
    this.s2cMac = s2cMac;
  }

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the MAC object.
   *
   * <p>For server session, it should return the C2S MAC, since C2S is the incoming direction, while
   * client session, it should return the S2C MAC.</p>
   *
   * @return the MAC object for incoming packet
   */
  public abstract Mac getInMac();

  public abstract void setInMac(Mac inMac);

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the MAC object.
   *
   * <p>For server session, it should return the S2C MAC, since S2C is the outgoing direction, while
   * client session, it should return the C2S MAC.</p>
   *
   * @return the Mac object for outgoing packet
   */
  public abstract Mac getOutMac();

  public abstract void setOutMac(Mac outMac);

  // Size of the MAC's block from client to server
  /** Returns the block size of the MAC for packet from client to server */
  protected int getC2sMacSize() {
    return c2sMacSize;
  }
  /** Replaces the block size of the MAC for packet from client to server */
  protected void setC2sMacSize(int c2sMacSize) {
    this.c2sMacSize = c2sMacSize;
  }

  // Size of the MAC's block from server to client
  /** Returns the block size of the MAC for packet from server to client */
  protected int getS2cMacSize() {
    return s2cMacSize;
  }
  /** Replaces the block size of the MAC for packet from server to client */
  protected void setS2cMacSize(int s2cMacSize) {
    this.s2cMacSize = s2cMacSize;
  }

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the MAC size.
   *
   * <p>For server session, it should return the C2S MAC size, since C2S is the incoming direction,
   * while client session, it should return the S2C MAC size.</p>
   *
   * @return the MAC size for incoming MAC
   */
  public abstract int getInMacSize();

  public abstract void setInMacSize(int inMacSize);

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the MAC size.
   *
   * <p>For server session, it should return the S2C MAC size, since S2C is the outgoing direction,
   * while client session, it should return the C2S MAC size.</p>
   *
   * @return the Mac size for outgoing MAC
   */
  public abstract int getOutMacSize();

  public abstract void setOutMacSize(int outMacSize);

  // Default size of the MAC's block from client to server
  /** Returns the default block size of the MAC for packet from client to server */
  protected int getC2sDefMacSize() {
    return c2sDefMacSize;
  }
  /** Replaces the default block size of the MAC for packet from client to server */
  protected void setC2sDefMacSize(int c2sDefMacSize) {
    this.c2sDefMacSize = c2sDefMacSize;
  }

  // Default size of the MAC's block from server to client
  /** Returns the default block size of the MAC for packet from server to client */
  protected int getS2cDefMacSize() {
    return s2cDefMacSize;
  }
  /** Replaces the default block size of the MAC for packet from server to client */
  protected void setS2cDefMacSize(int s2cDefMacSize) {
    this.s2cDefMacSize = s2cDefMacSize;
  }

  public abstract void setInDefMacSize(int inDefMacSize);

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the default MAC size.
   *
   * <p>For server session, it should return the S2C default MAC size, since S2C is the outgoing
   * direction, while client session, it should return the C2S default MAC size.</p>
   *
   * @return the default Mac size for outgoing MAC
   */
  public abstract int getOutDefMacSize();

  public abstract void setOutDefMacSize(int outDefMacSize);

  /*
   * Compression
   */
  // Compression from client to server
  /** Returns the compression object for packet packet from client to server */
  protected Compression getC2sCompression() {
    return c2sCompression;
  }
  /** Replaces the compression object for packet packet from client to server */
  protected void setC2sCompression(Compression c2sCompression) {
    this.c2sCompression = c2sCompression;
  }

  // Compression from server to client
  /** Returns the compression object for packet packet from server to client */
  protected Compression getS2cCompression() {
    return s2cCompression;
  }
  /** Replaces the compression object for packet packet from server to client */
  protected void setS2cCompression(Compression s2cCompression) {
    this.s2cCompression = s2cCompression;
  }

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the compression object.
   *
   * <p>For server session, it should return the C2S compression, since C2S is the incoming
   * direction, while client session, it should return the S2C compression.</p>
   *
   * @return the compression object for incoming packet
   */
  public abstract Compression getInCompression();

  public abstract void setInCompression(Compression inCompression);

  /**
   * By abstracting the session type - client or server, this method simplifies the function to get
   * the compression object.
   *
   * <p>For server session, it should return the S2C compression, since S2C is the outgoing
   * direction, while client session, it should return the C2S compression.</p>
   *
   * @return the compression object for outgoing packet
   */
  public abstract Compression getOutCompression();

  public abstract void setOutCompression(Compression outCompression);


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
   * Obtains the remote ip address and port where this channel is connected to.
   */
  private String getRemoteAddress() {
    if (remoteAddr == null) {
      SocketAddress sa = channel.remoteAddress();
      if (sa instanceof InetSocketAddress) {
        InetSocketAddress isa = (InetSocketAddress) sa;

        remoteAddr = isa.getAddress().getHostAddress() + ":" + isa.getPort();
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

  public abstract void requestUserAuthRequest(String username, String service, String method);

  public abstract void requestServiceRequest();

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
    return createBuffer(DEFAULT_BUFFER_SIZE);
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
  protected ByteBuf createMessage(byte msgId) {
    ByteBuf msg = createBuffer();

    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(msgId);

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

  public abstract void replyAccept(String svcName);

  public Service getService() {
    return this.service;
  }
  
  /**
   * RFC 4254:<br/>
   * Data transfer is done with messages of the following type.
   * <pre>
   *    byte      SSH_MSG_CHANNEL_DATA
   *    uint32    recipient channel
   *    string    data
   * </pre>
   *
   * <p>
   * The maximum amount of data allowed is determined by the maximum
   * packet size for the channel, and the current window size, whichever
   * is smaller.  The window size is decremented by the amount of data
   * sent.  Both parties MAY ignore all extra data sent after the allowed
   * window is empty.
   * </p>
   *
   * <p>
   * Implementations are expected to have some limit on the SSH transport
   * layer packet size (any limit for received packets MUST be 32768 bytes
   * or larger, as described in [SSH-TRANS]).  The implementation of the
   * SSH connection layer
   * <ul>
   *   <li>MUST NOT advertise a maximum packet size that would result in
   *    transport packets larger than its transport layer is willing to
   *    receive.</li>
   *   <li>MUST NOT generate data packets larger than its transport layer is
   *    willing to send, even if the remote end would be willing to accept
   *    very large packets.
   * </ul>
   * </p>
   * @see <a href="https://tools.ietf.org/html/rfc4254#section-5.2">Data Transfer</a>
   */
  public void replyChannelData(int recipient, byte[] data, int off, int len) {
    ByteBuf cd = createMessage(SshMessage.SSH_MSG_CHANNEL_DATA);

    cd.writeInt(recipient);
    cd.writeInt(data.length);
    cd.writeBytes(data, off, len);

    channel.writeAndFlush(cd);
  }

  /**
   * RFC 4254:<br/>
   * Additionally, some channels can transfer several types of data.  An
   * example of this is stderr data from interactive sessions.  Such data
   * can be passed with SSH_MSG_CHANNEL_EXTENDED_DATA messages, where a
   * separate integer specifies the type of data.  The available types and
   * their interpretation depend on the type of channel.
   * <pre>
   *    byte      SSH_MSG_CHANNEL_EXTENDED_DATA
   *    uint32    recipient channel
   *    uint32    data_type_code
   *    string    data
   * </pre>
   *
   * <p>
   * Data sent with these messages consumes the same window as ordinary
   * data.
   * </p>
   *
   * <p>
   * Currently, only the following type is defined.  Note that the value
   * for the 'data_type_code' is given in decimal format for readability,
   * but the values are actually uint32 values.
   * <pre>
   *             Symbolic name                  data_type_code
   *             -------------                  --------------
   *           SSH_EXTENDED_DATA_STDERR               1
   * </pre>
   * </p>
   * <p>
   * Extended Channel Data Transfer 'data_type_code' values MUST be
   * assigned sequentially.  Requests for assignments of new Extended
   * Channel Data Transfer 'data_type_code' values and their associated
   * Extended Channel Data Transfer 'data' strings, in the range of
   * 0x00000002 to 0xFDFFFFFF, MUST be done through the IETF CONSENSUS
   * method as described in [RFC2434].  The IANA will not assign Extended
   * Channel Data Transfer 'data_type_code' values in the range of
   * 0xFE000000 to 0xFFFFFFFF.  Extended Channel Data Transfer
   * 'data_type_code' values in that range are left for PRIVATE USE, as
   * described in [RFC2434].  As is noted, the actual instructions to the
   * IANA are in [SSH-NUMBERS].
   * </p>
   *
   * @see <a href="https://tools.ietf.org/html/rfc4254#section-5.2">Data Transfer</a>
   */
  public void replyChannelExtendedData(int recipient, byte[] data, int off, int len) {
    ByteBuf ced = createMessage(SshMessage.SSH_MSG_CHANNEL_EXTENDED_DATA);

    ced.writeInt(recipient);
    ced.writeInt(SshConstant.SSH_EXTENDED_DATA_STDERR);
    ced.writeInt(data.length);
    ced.writeBytes(data, off, len);

    channel.writeAndFlush(ced);
  }
  
  @Override
  public String toString() {
    return getUsername() + "@" + getRemoteAddress();
  }
}
