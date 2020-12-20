package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractOpenClose;
import io.github.grantchan.sshengine.common.AbstractSession;

import java.io.IOException;

public abstract class AbstractChannel extends AbstractOpenClose implements Channel {

  /** Channel identifier */
  private final int id;

  /** The channel identifier used when talking to remote peer */
  private int peerId;

  /** The session that this channel belongs to */
  private final AbstractSession session;

  public AbstractChannel(AbstractSession session) {
    this.session = session;

    this.id = register(this);
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
   * Close a channel synchronously
   *
   * @throws IOException If failed to close the channel
   */
  @Override
  public void close() throws IOException {
    unRegister(id);  // In a session, once the channel is closed, its id will never be used again

    logger.debug("[{}] channel ({}) is unregistered.", session, this);

    super.close();
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + " [id=" + id + " peerId=" + peerId + "]";
  }
}
