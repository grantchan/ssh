package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.server.connection.ChannelInputStream;
import io.github.grantchan.sshengine.server.connection.ChannelOutputStream;
import io.github.grantchan.sshengine.util.DaemonThreadFactory;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class SessionChannel extends AbstractClientChannel {

  private static final int DEFAULT_THREAD_POOL_SIZE = 8;

  private static final ExecutorService drainPool =
      Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE, new DaemonThreadFactory());

  protected final Object lock = new Object();

  private Future<?> drainer;

  protected final ChannelInputStream chIn = new ChannelInputStream(this);
  protected final ChannelOutputStream chOut = new ChannelOutputStream(this, false);
  protected final ChannelOutputStream chErr = new ChannelOutputStream(this, false);

  public SessionChannel(ClientSession session) {
    super(session);
  }

  @Override
  public String getType() {
    return "session";
  }

  @Override
  protected void doOpen() throws IOException {
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
          e.printStackTrace();
        }
      }
    });
  }

  @Override
  protected void doClose() throws IOException {
    synchronized (lock) {
      lock.notifyAll();
    }

    if (!drainer.isDone() || !drainer.isCancelled()) {
      drainer.cancel(true);
    }
  }

  @Override
  public void waitFor(State state, long timeout, TimeUnit unit) {
    synchronized (lock) {
      try {
        if (timeout <= 0) {
          lock.wait();
        } else {
          lock.wait(unit.toMillis(timeout));
        }
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }
}
