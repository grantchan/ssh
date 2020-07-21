package io.github.grantchan.sshengine.common.connection;

import java.io.IOException;

public class WindowClosedException extends IOException {

  private static final long serialVersionUID = -4769250011171383902L;

  public WindowClosedException(String msg) {
    this(msg, null);
  }

  public WindowClosedException(String msg, Throwable cause) {
    super(msg, cause);
  }
}
