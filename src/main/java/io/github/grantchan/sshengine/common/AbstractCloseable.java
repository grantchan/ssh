package io.github.grantchan.sshengine.common;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/**
 * This class overrides implements Closeable interface to provide asynchronous closure process.
 */
public abstract class AbstractCloseable extends AbstractLogger implements Closeable {

  protected enum State {
    OPENED, CLOSING, CLOSED
  }

  protected final AtomicReference<State> state = new AtomicReference<>(State.OPENED);

  /**
   * @return true if it's closed or closing, otherwise, false
   */
  public boolean isClosed() {
    return state.get() != State.OPENED;
  }

  /**
   * This method needs to be overridden to provide more immediate closure instructions from
   * inherited class.
   */
  protected void doCloseForcibly() {
    state.set(State.CLOSED);
  }

  /**
   * This method needs to be overridden to provide graceful closure instructions from inherited
   * class.
   */
  protected CompletableFuture<Boolean> doCloseGracefully() throws IOException {
    return CompletableFuture.completedFuture(false);
  }

  public CompletableFuture<Boolean> close(boolean gracefully) throws IOException {
    CompletableFuture<Boolean> result = CompletableFuture.completedFuture(true);

    if (gracefully) {
      if (state.compareAndSet(State.OPENED, State.CLOSING)) {
        logger.debug("{} is closing...", this);

        doCloseGracefully().whenComplete((closed, e) -> {
          if (closed && state.get() == State.CLOSED) {
            logger.debug("{} is closed", this);
          } else {
            doCloseForcibly();

            if (e == null) {
              logger.debug("{} is closed", this);
            } else {
              result.completeExceptionally(e);

              logger.debug("{} is closed with exception", this);
            }
          }
          result.complete(true);
        });
      } else {
        logger.debug("It's closing already");

        result.complete(true);
      }
    } else {
      if (state.compareAndSet(State.OPENED, State.CLOSING) || state.get() == State.CLOSING) {
        logger.debug("{} is closing...", this);

        doCloseForcibly();

        logger.debug("{} is closed", this);
      } else {
        logger.debug("It's closed already");
      }
      result.complete(true);
    }

    return result;
  }

  @Override
  public void close() throws IOException {
    close(this);
  }

  private static void close(AbstractCloseable c) throws IOException {
    if (c == null) {
      return;
    }
    c.close(true);
  }
}