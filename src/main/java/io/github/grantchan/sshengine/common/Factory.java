package io.github.grantchan.sshengine.common;

public interface Factory<T> {

  /**
   * @return create a new instance
   */
  T create();
}
