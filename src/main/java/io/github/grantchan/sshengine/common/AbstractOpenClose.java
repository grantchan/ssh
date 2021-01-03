package io.github.grantchan.sshengine.common;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractOpenClose extends AbstractLogger implements AsyncCloseable {

  protected enum State {
    OPENED, CLOSING, CLOSED
  }

  protected final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  /**
   *
   * @return {@code True} if the channel is opened, otherwise, {@code False}
   */
  @Override
  public boolean isOpen() {
    return state.get() == State.OPENED;
  }

  /**
   * Opens a channel synchronously
   *
   * @throws IOException If failed to open the channel
   */
  public void open() throws IOException {
    state.set(State.OPENED);
  }

  @Override
  public void close() throws IOException {
    state.set(State.CLOSED);
  }

  @Override
  public CompletableFuture<Boolean> closeAsync() throws IOException {
    return CompletableFuture.completedFuture(false);
  }

  /**
   * Depends on the boolean value of the parameter - gracefully, this method closes this object in
   * a either graceful way or forcible way.
   *
   * <p>
   * Internally, if graceful, the {@link #closeAsync()} is called, if the return of that is
   * false - meaning the status of this object is not closed, the {@link #close()} will be invoked.
   * If not graceful, this method simply calls the {@link #close()}
   * </p>
   *
   * @param gracefully indicates to close this object gracefully or not
   * @return A {@link CompletableFuture} object referencing the close result
   *
   * @see #close()
   * @see #closeAsync()
   */
  public CompletableFuture<Boolean> close(boolean gracefully) throws IOException {
    if (!gracefully) {
      if (state.compareAndSet(State.OPENED, State.CLOSING) || state.get() == State.CLOSING) {
        logger.debug("{} is closing...", this);

        close();

        logger.debug("{} is closed", this);
      } else {
        logger.debug("It's closed already");
      }

      return CompletableFuture.completedFuture(true);
    }

    if (state.compareAndSet(State.OPENED, State.CLOSING)) {
      logger.debug("{} is closing...", this);

      return closeAsync().thenApply(closed -> {
        if (closed && state.get() == State.CLOSED) {
          logger.debug("{} is closed", this);
        } else {
          try {
            close();

            logger.debug("{} is closed", this);
          } catch (IOException ioe) {
            logger.debug("{} is closed with exception - {}", this, ioe);

            return false;
          }
        }
        return true;
      });
    }

    logger.debug("It's closing already");

    return CompletableFuture.completedFuture(true);
  }
}
