package io.github.grantchan.SshEngine.common;

public interface Factory<T> {

  /**
   * @return create a new instance
   */
  T create();
}
