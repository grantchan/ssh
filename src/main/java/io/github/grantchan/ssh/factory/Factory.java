package io.github.grantchan.ssh.factory;

public interface Factory<T> {

  /**
   * @return create a new instance
   */
  T create();
}
