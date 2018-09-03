package io.github.grantchan.ssh.common;

public interface Factory<T> {

  T create() throws Exception;
}
