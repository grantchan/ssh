package io.github.grantchan.SshEngine.common.connection;

public class SessionChannel implements Channel {

  private final int id;

  public SessionChannel() {
    this.id = register(this);
  }

  @Override
  public int getId() {
    return id;
  }
}
