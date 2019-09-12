package io.github.grantchan.SshEngine.common.connection;

import io.github.grantchan.SshEngine.common.Session;

public class SessionChannel extends AbstractChannel {

  // Local and remote windows
  private Window localWnd, remoteWnd;

  public SessionChannel(Session session) {
    super(session);
  }

  @Override
  public void doOpen(int rwndsize, int rpksize) throws Exception {
    localWnd = new Window(this);
    remoteWnd = new Window(this, rwndsize, rpksize);

    super.doOpen(rwndsize, rpksize);
  }

  @Override
  public Window getLocalWindow() {
    return localWnd;
  }

  @Override
  public Window getRemoteWindow() {
    return remoteWnd;
  }
}
