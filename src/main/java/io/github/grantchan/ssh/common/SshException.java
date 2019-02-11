package io.github.grantchan.ssh.common;

import java.io.IOException;

public class SshException extends IOException {

  private static final long serialVersionUID = -2275187066710839249L;

  private final int disconnectReason;

  public int getDisconnectReason() {
    return disconnectReason;
  }

  public SshException(int disconnectReason, String message) {
    this(disconnectReason, message, null);
  }

  public SshException(int disconnectReason, String message, Throwable cause) {
    super(message, cause);
    this.disconnectReason = disconnectReason;
  }
}
