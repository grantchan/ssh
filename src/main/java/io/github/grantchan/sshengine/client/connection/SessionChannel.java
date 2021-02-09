package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class SessionChannel extends AbstractClientChannel {

  protected final Object lock = new Object();

  public SessionChannel(ClientSession session, CompletableFuture<ClientChannel> openFuture) {
    super(session, openFuture);
  }

  @Override
  public String getType() {
    return "session";
  }

  @Override
  protected void doOpen() throws IOException {
  }

  @Override
  protected void doClose() throws IOException {
    synchronized (lock) {
      lock.notifyAll();
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
