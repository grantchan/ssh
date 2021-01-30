package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.SshChannelException;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.server.ServerSession;

import java.io.IOException;
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
   * Open a channel synchronously
   */
  @Override
  public void open() throws SshChannelException {
    if (isOpen()) {
      logger.debug("[{}] This channel ({}) is already opened - status:{}", session, this, getState());

      return;
    }

    logger.debug("[{}] Channel ({}) is being opened...", session, this);

    /*
     * The remote side then decides whether it can open the channel, and responds with either
     * SSH_MSG_CHANNEL_OPEN_CONFIRMATION or SSH_MSG_CHANNEL_OPEN_FAILURE.
     *
     * https://tools.ietf.org/html/rfc4254#section-5.1
     */
    try {
      this.id = register(this);

      logger.debug("[{}] channel ({}) is registered.", session, this);

      setState(State.OPENED);

      logger.debug("[{}] Channel ({}) is opened - status:{}", session, this, getState());

      session.replyChannelOpenConfirmation(peerId, getId(), localWnd.getMaxSize(), localWnd.getPacketSize());
    } catch (Exception ex) {
      logger.debug("[{}] Failed to open channel ({}) - status:{}", session, this, getState());

      unRegister(getId());

      int reason = 0;
      String message = "Error while opening channel, id: " + peerId + ex.getMessage();
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
    remoteWnd.close();

    unRegister(id);  // In a session, once the channel is closed, its id will never be used again

    logger.debug("[{}] channel ({}) is unregistered.", session, this);

    setState(State.CLOSED);

    logger.debug("[{}] channel ({}) is closed", getSession(), this);
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
}
