package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.AbstractChannel;
import io.github.grantchan.sshengine.common.connection.Window;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public abstract class AbstractClientChannel extends AbstractChannel {

  private final Window localWnd = new Window(this, "client/local");
  private Window remoteWnd;

  private CompletableFuture<Boolean> openFuture;

  public AbstractClientChannel(AbstractSession session) {
    super(session);
  }

  public abstract String getType();

  @Override
  public void init(int peerId, int rWndSize, int rPkSize) {
    super.init(peerId, rWndSize, rPkSize);

    remoteWnd = new Window(this, "client/remote");
  }

  @Override
  public void close() throws IOException {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(true);
    }

    localWnd.close();
    remoteWnd.close();

    super.close();
  }

  @Override
  public void open() throws IOException {
    //
    //
  }

  @Override
  public CompletableFuture<Boolean> openAsync() throws IOException {
    ClientSession session = (ClientSession) getSession();

    openFuture = new CompletableFuture<>();

    //session.sendChannelOpen(getType(), getId(), localWnd.getMaxSize(), localWnd.getPacketSize());

    return openFuture;
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
  public void handleWindowAdjust(ByteBuf req) {

  }

  @Override
  public void handleData(ByteBuf req) throws IOException {

  }

  @Override
  public void handleEof(ByteBuf req) throws IOException {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(true);
    }

  }

  @Override
  public void handleClose(ByteBuf req) throws IOException {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(true);
    }

  }

  @Override
  public void handleRequest(ByteBuf req) throws IOException {

  }

  public void handleOpenConfirmation(ByteBuf req) throws IOException {
    openFuture.complete(true);

    // init(peerId, rWndSize, rPkSize);
  }
}
