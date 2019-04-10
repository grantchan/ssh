package io.github.grantchan.ssh.util;

import java.io.File;
import java.nio.file.Path;

public final class System {

  public static Path getUserHomeFolder() {
    return new File(java.lang.System.getProperty("user.home")).toPath().toAbsolutePath().normalize();
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private System() {}
}
