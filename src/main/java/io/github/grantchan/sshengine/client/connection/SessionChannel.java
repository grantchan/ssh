package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public class SessionChannel extends AbstractClientChannel {

  public SessionChannel(ClientSession session, CompletableFuture<AbstractClientChannel> openFuture) {
    super(session, openFuture);
  }

  @Override
  public String getType() {
    return "session";
  }

  @Override
  protected void open0() throws IOException {

  }
}
