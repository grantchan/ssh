package io.github.grantchan.sshengine.common;

public interface CommonState {

  enum State {
    OPENED, CLOSING, CLOSED
  }

  State getState();

  void setState(State state);
}
