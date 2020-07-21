package io.github.grantchan.sshengine.server.connection;

import java.io.IOException;

@FunctionalInterface
public interface ExitCallback {

  void onExit(int exitValue) throws IOException;
}
