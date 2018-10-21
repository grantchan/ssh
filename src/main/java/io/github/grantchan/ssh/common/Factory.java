package io.github.grantchan.ssh.common;

public interface Factory<T> {

  /**
   * @return create a new instance
   */
  T create();
}
