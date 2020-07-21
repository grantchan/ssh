package io.github.grantchan.sshengine.common.connection;

import java.io.InterruptedIOException;

public class WindowTimeoutException extends InterruptedIOException {

  private static final long serialVersionUID = 5540541227635097252L;

  public WindowTimeoutException(String msg) {
    super(msg);
  }
}
