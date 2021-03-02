package io.github.grantchan.sshengine.common;

import java.util.function.BiConsumer;

public interface CommonState {

  enum State {
    OPENED, CLOSING, CLOSED
  }

  State getState();

  void setState(State state);

  default void whenStateChanged(BiConsumer<State, ? super Throwable> listener) {}
}
