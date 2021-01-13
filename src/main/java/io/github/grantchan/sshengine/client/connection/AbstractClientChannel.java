package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.connection.AbstractChannel;
import io.github.grantchan.sshengine.common.connection.Window;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public abstract class AbstractClientChannel extends AbstractChannel {

  private final Window localWnd = new Window(this, "client/local");
  private Window remoteWnd;

  private CompletableFuture<AbstractClientChannel> openFuture;

  public AbstractClientChannel(ClientSession session,
                               CompletableFuture<AbstractClientChannel> openFuture) {
    super(session);

    this.openFuture = openFuture;
  }

  public abstract String getType();

  @Override
  public void init(int peerId, int rWndSize, int rPkSize) {
    super.init(peerId, rWndSize, rPkSize);

    remoteWnd = new Window(this, "client/remote", rWndSize, rPkSize);
  }

  @Override
  public void close() throws IOException {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(this);
    }

    localWnd.close();
    remoteWnd.close();

    super.close();
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
  public void handleRequest(ByteBuf req) throws IOException {

  }

  public void handleOpenConfirmation(ByteBuf req) {
    int peerId = req.readInt();
    int rWndSize = req.readInt();
    int rPkSize = req.readInt();

    init(peerId, rWndSize, rPkSize);

    try {
      open0();
    } catch (IOException e) {
      openFuture.completeExceptionally(e);

      return;
    }

    openFuture.complete(this);
  }

  protected abstract void open0() throws IOException;
}
