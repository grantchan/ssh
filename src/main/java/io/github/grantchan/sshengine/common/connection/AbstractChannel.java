package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractChannel extends AbstractLogger
                                      implements Channel {

  /** Channel identifier */
  private final int id;

  /** The session that this channel belongs to */
  private final AbstractSession session;

  /** The channel identifier used when talking to remote peer */
  private int peerId;

  /** The executor to run open/close tasks in asynchronous mode */
  private static final ExecutorService executor = Executors.newFixedThreadPool(3);

  /** Channel states */
  protected enum State { OPENED, CLOSING, CLOSED }

  /** Current state, initiated "Closed" */
  private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  public AbstractChannel(AbstractSession session) {
    this.session = session;

    this.id = register(this);
  }

  /**
   * @return the channel identifier
   */
  @Override
  public int getId() {
    return id;
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  /**
   * @return the channel identifier of remote side
   */
  public int getPeerId() {
    return peerId;
  }

  /**
   * Open a channel asynchronously
   */
  @Override
  public CompletableFuture<Boolean> open(int peerId, int rwndsize, int rpksize) {
    CompletableFuture<Boolean> future = new CompletableFuture<>();

    executor.submit(() -> {
      if (state.compareAndSet(State.CLOSED, State.OPENED)) {
        logger.debug("[{}] Channel ({}) is being opened...", session, this);

        try {
          this.peerId = peerId;

          doOpen(rwndsize, rpksize);

          logger.debug("[{}] Channel ({}) is opened - status:{}", session, this, state.get());

          future.complete(true);
        } catch (Exception e) {
          unRegister(id);

          logger.debug("[{}] Failed to open channel ({}) - status:{}", session, this, state.get());

          future.completeExceptionally(e);
        }
      } else {
        logger.debug("[{}] This channel ({}) is already opened - status:{}", session, this,
            state.get());

        future.complete(true);
      }
    });
    return future;
  }

  /**
   * Open a channel synchronously
   *
   * @param rwndsize Remote window size
   * @param rpksize Remote packet size
   * @throws Exception If failed to open the channel
   */
  protected void doOpen(int rwndsize, int rpksize) throws Exception {
    state.set(State.OPENED);
  }

  @Override
  public boolean isOpen() {
    return state.get() == State.OPENED;
  }

  /**
   * Close a channel asynchronously
   */
  @Override
  public CompletableFuture<Boolean> close() {
    CompletableFuture<Boolean> future = new CompletableFuture<>();

    executor.submit(() -> {
      if (state.compareAndSet(State.OPENED, State.CLOSING)) {
        logger.debug("[{}] Channel is being closed...", this);

        try {
          doClose();

          logger.debug("[{}] Channel is closed - {}", this, state.get());

          future.complete(true);
        } catch (Exception e) {
          logger.debug("[{}] Failed to close channel - {}", this, state.get());

          future.completeExceptionally(e);
        }
      } else {
        logger.debug("[{}] This channel is already closed - {}", this, state.get());

        future.complete(true);
      }
    });

    return future;
  }

  /**
   * Close a channel synchronously
   *
   * @throws Exception If failed to close the channel
   */
  protected void doClose() throws Exception {
    unRegister(this.id);  // In a session, once the channel is closed, its id will never be used
                          // again

    logger.debug("[{}] channel ({}) is unregistered.", session, this);

    state.set(State.CLOSED);
  }


  @Override
  public String toString() {
    return getClass().getSimpleName() + " [id=" + id + " peerId=" + peerId + "]";
  }
}
