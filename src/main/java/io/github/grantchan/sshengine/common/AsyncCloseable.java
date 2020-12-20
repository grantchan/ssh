package io.github.grantchan.sshengine.common;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;

/**
 * This class overrides implements Closeable interface to provide asynchronous closure process.
 */
public interface AsyncCloseable extends Closeable {

  /**
   * @return true if it's opened, otherwise, false
   */
  boolean isOpen();

  /**
   * This method needs to be overridden to provide more immediate closure instructions from
   * inherited class.
   */
  void close() throws IOException;

  /**
   * This method needs to be overridden to provide graceful closure instructions from inherited
   * class.
   */
  CompletableFuture<Boolean> closeAsync() throws IOException;
}