package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.util.DaemonThreadFactory;

import java.io.IOException;
import java.util.concurrent.*;

public class SessionChannel extends AbstractClientChannel {

  private static final int DEFAULT_THREAD_POOL_SIZE = 8;

  private static final ExecutorService drainPool =
      Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE, new DaemonThreadFactory());

  private Future<?> drainer;

  private static final ScheduledExecutorService delayer =
      new ScheduledThreadPoolExecutor(1, new DaemonThreadFactory());

  public SessionChannel(ClientSession session) {
    super(session);
  }

  @Override
  public String getType() {
    return "session";
  }

  @Override
  protected void doOpen() {
    drainer = drainPool.submit(() -> {
      Window remoteWnd = getRemoteWindow();
      int pkgSize = remoteWnd.getPacketSize();
      byte[] buf = new byte[pkgSize];

      while (State.CLOSED != getState()) {
        try {
          int n = in.read(buf, 0, buf.length);
          if (n < 0) {
            // send SSH_MSG_CHANNEL_EOF
            return;
          } else if (n > 0) {
            chOut.write(buf, 0, n);
          }
        } catch (IOException e) {
          logger.warn("Error happends while reading data from input stream - {}", e.getMessage());
        }
      }
    });
  }

  @Override
  protected void doClose() {
    if (!drainer.isDone() || !drainer.isCancelled()) {
      drainer.cancel(true);
    }
  }

  @Override
  public void waitFor(State state, long timeout, TimeUnit unit) {
    if (state == getState()) {
      return;
    }

    // the future event to signal once the channel state is changed to
    CompletableFuture<State> eventToWait = new CompletableFuture<>();

    // by setting the callback listener, above future event will be notified whenever it's completed
    // or ended up with exception
    whenStateChanged((current, cause) -> {
      if (cause != null) {
        eventToWait.completeExceptionally(cause);
      } else {
        eventToWait.complete(current);
      }
    });

    // use another future event to indicate the target event - eventToWait is ended
    CompletableFuture<Boolean> finish = CompletableFuture.supplyAsync(() -> {
      try {
        eventToWait.get();
      } catch (InterruptedException | ExecutionException e) {
        e.printStackTrace();

        return false;
      }

      logger.debug("{} State has changed to {}", this, getState());

      return true;
    });

    CompletableFuture<Boolean> cancel = CompletableFuture.supplyAsync(() -> {
      delayer.schedule(() -> eventToWait.cancel(true), timeout, unit);

      logger.debug("{} Time out before state is changed, state remains: {}", this, getState());

      return false;
    });

    try {
      finish.acceptEither(cancel, b -> eventToWait.cancel(!b)).get();
    } catch (InterruptedException | ExecutionException e) {
      e.printStackTrace();
    } finally {
      // to clean up: whenever what happens, it's necessary to fall back the listener
      whenStateChanged(null);
    }
  }
}
