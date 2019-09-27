package io.github.grantchan.sshengine.common;

import java.io.IOException;

public class SshException extends IOException {

  private static final long serialVersionUID = -2275187066710839249L;

  private final int reason;

  public int getReason() {
    return reason;
  }

  public SshException(int reason, String message) {
    this(reason, message, null);
  }

  public SshException(int reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }
}
