package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.SshChannelException;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.server.ServerSession;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractServerChannel extends AbstractLogger implements ServerChannel {

  /** Current state of this channel, initially closed */
  private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  /** Channel identifier */
  private int id;

  /** The channel identifier used when talking to remote peer */
  private int peerId;

  /** The session that this channel belongs to */
  private final ServerSession session;

  /** Local and remote windows */
  private final Window localWnd = new Window(this, "client/local");
  private Window remoteWnd;

  public AbstractServerChannel(ServerSession session) {
    this.session = session;
  }

  @Override
  public void init(int peerId, int rWndSize, int rPkSize) {
    this.peerId = peerId;

    remoteWnd = new Window(this, "server/remote", rWndSize, rPkSize);
  }

  /**
   * @return the channel identifier
   */
  @Override
  public int getId() {
    return id;
  }

  /**
   * @return the channel identifier of remote side
   */
  @Override
  public int getPeerId() {
    return peerId;
  }

  /**
   * @return the session that this channel belongs to
   */
  @Override
  public AbstractSession getSession() {
    return session;
  }

  /**
   * Opens a channel synchronously
   *
   * This method opens a channel by registering itself, if succeeded, it sends the
   * {@link io.github.grantchan.sshengine.arch.SshMessage#SSH_MSG_CHANNEL_OPEN_CONFIRMATION} message
   * to the client, otherwise, it sends
   * {@link io.github.grantchan.sshengine.arch.SshMessage#SSH_MSG_CHANNEL_OPEN_FAILURE} to notify
   * the client this process has failed at server side, meanwhile, {@link SshChannelException} will
   * be thrown.
   *
   * @throws SshChannelException when the opening process is failed
   */
  @Override
  public void open() throws SshChannelException {
    if (isOpen()) {
      logger.debug("{} This channel is already opened - status:{}", this, getState());

      return;
    }

    logger.debug("{} Channel is being opened...", this);

    /*
     * The remote side then decides whether it can open the channel, and responds with either
     * SSH_MSG_CHANNEL_OPEN_CONFIRMATION or SSH_MSG_CHANNEL_OPEN_FAILURE.
     *
     * https://tools.ietf.org/html/rfc4254#section-5.1
     */
    try {
      this.id = register(this);

      logger.debug("{} Channel is registered.", this);

      setState(State.OPENED);

      logger.debug("{} Channel is opened - status:{}", this, getState());

      int wndSize = localWnd.getMaxSize();
      int pkgSize = localWnd.getPacketSize();
      session.replyChannelOpenConfirmation(peerId, id, wndSize, pkgSize);
    } catch (Exception ex) {
      logger.debug("{} Failed to open channel - status:{}", this, getState());

      unRegister(getId());

      /*
       * Reason code for channel open error should be any one of these:
       *
       * SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
       * SSH_OPEN_CONNECT_FAILED
       * SSH_OPEN_UNKNOWN_CHANNEL_TYPE
       * SSH_OPEN_RESOURCE_SHORTAGE
       */
      int reason = SshMessage.SSH_OPEN_RESOURCE_SHORTAGE;
      String message = "Error happened while opening channel, id: " + peerId + ex.getMessage();
      session.replyChannelOpenFailure(peerId, reason, message, "");

      throw new SshChannelException(ex);
    }
  }

  @Override
  public boolean isOpen() {
    return getState() == State.OPENED;
  }

  /**
   * Close a channel synchronously
   *
   * @throws IOException If failed to close the channel
   */
  @Override
  public void close() throws IOException {
    localWnd.close();
    Optional.ofNullable(remoteWnd).ifPresent(Window::close);

    unRegister(id); // In a session, once the channel is closed, its id will never be used again

    logger.debug("{} Channel is unregistered.", this);

    setState(State.CLOSED);

    logger.debug("{} Channel is closed", this);
  }

  @Override
  public Window getLocalWindow() {
    return localWnd;
  }

  @Override
  public Window getRemoteWindow() {
    return remoteWnd;
  }

  @Override
  public State getState() {
    return state.get();
  }

  @Override
  public void setState(State state) {
    this.state.set(state);
  }

  @Override
  public String toString() {
    return "[id=" + getId() + ", peer id=" + getPeerId() + ", session=" + session + "]";
  }
}
