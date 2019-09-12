package io.github.grantchan.sshengine.common;

import java.util.concurrent.CompletableFuture;

public interface Closeable extends java.io.Closeable {

  /**
   * Close asynchronously
   *
   * @return A CompletableFuture object as a handle to the result of the asynchronous close process,
   *         once the process is finish, the result can be accessed by this object.
   */
  CompletableFuture<Boolean> closeGracefully();

  @Override
  default void close() {
    closeGracefully();
  }
}
