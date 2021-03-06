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
          logger.warn("Error happened while reading data from input stream - {}", e.getMessage());
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

    // the future event to signal once the channel state is changed to the state in the parameter
    CompletableFuture<State> eventToWait = new CompletableFuture<>();

    // by setting the callback listener, the above future event will be notified whenever it's
    // completed or ended up with exception
    whenStateChanged((current, cause) -> {
      if (current == state) {
        if (cause != null) {
          eventToWait.completeExceptionally(cause);
        } else {
          eventToWait.complete(current);
        }
      }
    });

    CompletableFuture<Boolean> timeOut = new CompletableFuture<>();
    delayer.schedule(() -> eventToWait.cancel(true), timeout, unit);

    // use another future event to indicate the target event - eventToWait is ended
    CompletableFuture<Boolean> finish =
      CompletableFuture.supplyAsync(() -> {
        try {
          eventToWait.get();
        } catch (InterruptedException | ExecutionException e) {
          e.printStackTrace();

          return false;
        }

        logger.debug("{} State has changed to {}", this, getState());

        return true;
      });

    try {
      finish.acceptEither(timeOut, done -> eventToWait.cancel(!done)).get();
    } catch (InterruptedException | ExecutionException e) {
      // ignore
    } finally {
      // to clean up: whatever happens, it's necessary to fall back the listener
      whenStateChanged(null);
    }
  }
}
