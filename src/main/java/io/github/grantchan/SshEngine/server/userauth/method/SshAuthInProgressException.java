package io.github.grantchan.SshEngine.server.userauth.method;

import java.io.IOException;

public class SshAuthInProgressException extends IOException {

  private static final long serialVersionUID = -2463574898488067679L;

  public SshAuthInProgressException(String message) {
    this(message, null);
  }

  public SshAuthInProgressException(String message, Throwable cause) {
    super(message);

    if (cause != null) {
      initCause(cause);
    }
  }
}
