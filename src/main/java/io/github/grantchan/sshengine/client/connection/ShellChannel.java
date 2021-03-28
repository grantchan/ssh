package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;

public class ShellChannel extends SessionChannel {

  public ShellChannel(ClientSession session) {
    super(session);
  }

  @Override
  protected void doOpen() {
    ClientSession session = (ClientSession) getSession();

    session.sendChannelShell(getPeerId());

    super.doOpen();
  }
}
