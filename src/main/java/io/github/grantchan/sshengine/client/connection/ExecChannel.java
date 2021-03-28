package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.client.ClientSession;

import java.util.Objects;

public class ExecChannel extends SessionChannel {

  private final String command;

  public ExecChannel(ClientSession session, String command) {
    super(session);

    this.command = Objects.requireNonNull(command, "Invalid parameter - command is null");
  }

  @Override
  protected void doOpen() {
    ClientSession session = (ClientSession) getSession();

    session.sendChannelExec(getPeerId(), command);

    super.doOpen();
  }
}
