package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.SshChannelException;
import io.github.grantchan.sshengine.common.connection.Window;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractClientChannel extends AbstractLogger implements ClientChannel {

  /** Current state of this channel, initially closed */
  private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  /** Channel identifier */
  private int id;

  /** The channel identifier used when talking to remote peer */
  private int peerId;

  /** The session that this channel belongs to */
  private final ClientSession session;

  /** Local and remote windows */
  private final Window localWnd = new Window(this, "client/local");
  private Window remoteWnd;

  /**
   * The future object used by creator of this object, usually the session, to indicate the
   * completeness of the opening process
   */
  private final CompletableFuture<ClientChannel> openFuture;

  public AbstractClientChannel(ClientSession session,
                               CompletableFuture<ClientChannel> openFuture) {
    this.session = session;
    this.openFuture = openFuture;
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

  public abstract String getType();

  @Override
  public void open() throws SshChannelException {
    this.id = register(this);

    logger.debug("[{}] channel ({}) is registered.", session, this);

    setState(State.OPENED);

    int wndSize = localWnd.getMaxSize();
    int pkgSize = localWnd.getPacketSize();

    session.sendChannelOpen(getType(), id, wndSize, pkgSize)
           .addListener(l -> {
             Throwable cause = l.cause();
             if (cause != null) {
               openFuture.completeExceptionally(cause);
             } else if (l.isCancelled()) {
               openFuture.cancel(true);
             }
           });
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
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(this);
    }

    localWnd.close();
    if (remoteWnd != null) {
      remoteWnd.close();
    }

    unRegister(id);  // In a session, once the channel is closed, its id will never be used again

    logger.debug("[{}] channel ({}) is unregistered.", session, this);

    setState(State.CLOSED);
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
  public void handleEof(ByteBuf req) throws IOException {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(this);
    }
  }

  @Override
  public void handleClose(ByteBuf req) throws IOException {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(this);
    }
  }

  @Override
  public void handleOpenConfirmation(ByteBuf req) {
    peerId = req.readInt();

    int rWndSize = req.readInt();
    int rPkSize = req.readInt();

    remoteWnd = new Window(this, "client/remote", rWndSize, rPkSize);

    try {
      doOpen();
    } catch (IOException e) {
      openFuture.completeExceptionally(e);

      return;
    }

    openFuture.complete(this);
  }

  @Override
  public void handleOpenFailure(ByteBuf req) {
    try {
      close();
    } catch (IOException e) { // must catch exception here, unless we want to disconnect this
                              // whole session.
      logger.warn("[{}] Failed to open channel.", session);
    }
  }

  protected abstract void doOpen() throws IOException;

  @Override
  public State getState() {
    return state.get();
  }

  @Override
  public void setState(State state) {
    this.state.set(state);
  }
}
