package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.AbstractChannel;
import io.github.grantchan.sshengine.common.connection.SshChannelException;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.server.ServerSession;

import java.io.IOException;

public abstract class AbstractServerChannel extends AbstractChannel {

  // Local and remote windows
  private final Window localWnd = new Window(this, "server/local");
  private Window remoteWnd;

  public AbstractServerChannel(AbstractSession session) {
    super(session);
  }

  @Override
  public void init(int peerId, int rWndSize, int rPkSize) {
    super.init(peerId, rWndSize, rPkSize);

    remoteWnd = new Window(this, "server/remote", rWndSize, rPkSize);
  }

  @Override
  public void close() throws IOException {
    localWnd.close();
    remoteWnd.close();

    super.close();

    logger.debug("[{}] channel ({}) is closed", getSession(), this);
  }

  /**
   * Open a channel synchronously
   */
  @Override
  public void open() throws SshChannelException {
    ServerSession session = (ServerSession) getSession();

    if (isOpen()) {
      logger.debug("[{}] This channel ({}) is already opened - status:{}", session, this, state.get());

      return;
    }

    logger.debug("[{}] Channel ({}) is being opened...", session, this);

    int peerId = getPeerId();
    try {
      super.open();

      logger.debug("[{}] Channel ({}) is opened - status:{}", session, this, state.get());

      session.replyChannelOpenConfirmation(peerId, getId(), localWnd.getMaxSize(), localWnd.getPacketSize());
    } catch (IOException ex) {
      logger.debug("[{}] Failed to open channel ({}) - status:{}", session, this, state.get());

      unRegister(getId());

      int reason = 0;
      String message = "Error while opening channel, id: " + peerId + ex.getMessage();
      session.replyChannelOpenFailure(peerId, reason, message, "");

      throw new SshChannelException(ex);
    }
  }

  @Override
  public Window getLocalWindow() {
    return localWnd;
  }

  @Override
  public Window getRemoteWindow() {
    return remoteWnd;
  }
}
