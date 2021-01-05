package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.CommonState;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractChannel extends AbstractLogger implements Channel, CommonState {

  private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  /** Channel identifier */
  private int id;

  /** The channel identifier used when talking to remote peer */
  private int peerId;

  /** The session that this channel belongs to */
  private final AbstractSession session;

  public AbstractChannel(AbstractSession session) {
    this.session = session;
  }

  /**
   * Initialize the channel
   *
   * @param peerId Remote channel ID
   * @param rWndSize Remote window size
   * @param rPkSize Remote packet size
   */
  public void init(int peerId, int rWndSize, int rPkSize) {
    this.peerId = peerId;
  }

  @Override
  public State getState() {
    return state.get();
  }

  @Override
  public void setState(State state) {
    this.state.set(state);
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

  @Override
  public void open() throws IOException {
    this.id = register(this);

    logger.debug("[{}] channel ({}) is registered.", session, this);

    setState(State.OPENED);
  }

  /**
   * Close a channel synchronously
   *
   * @throws IOException If failed to close the channel
   */
  @Override
  public void close() throws IOException {
    unRegister(id);  // In a session, once the channel is closed, its id will never be used again

    logger.debug("[{}] channel ({}) is unregistered.", session, this);

    setState(State.CLOSED);
  }

  @Override
  public boolean isOpen() {
    return getState() == State.OPENED;
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + " [id=" + id + " peerId=" + peerId + "]";
  }
}
