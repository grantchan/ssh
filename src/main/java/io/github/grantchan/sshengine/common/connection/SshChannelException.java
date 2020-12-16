package io.github.grantchan.sshengine.common.connection;

import java.io.IOException;
import java.util.Objects;

/**
 * Represents an SSH channel exception
 */
public class SshChannelException extends IOException {

  private static final long serialVersionUID = 2445907434916166647L;

  public SshChannelException(String message) {
    this(message, null);
  }

  public SshChannelException(Throwable cause) {
    this(Objects.requireNonNull(cause, "Invalid parameter - cause is null").getMessage(), cause);
  }

  public SshChannelException(String message, Throwable cause) {
    super(message, cause);
  }
}