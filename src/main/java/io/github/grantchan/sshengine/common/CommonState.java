package io.github.grantchan.sshengine.common;

import java.io.IOException;

public interface CommonState {

  enum State {
    OPENED, CLOSING, CLOSED
  }

  State getState();

  void setState(State state);

/**
   * Opens a channel synchronously
   *
   * @throws IOException If failed to open the channel
   *//*

  public void open() throws IOException {
    state.set(State.OPENED);
  }

  @Override
  public void close() throws IOException {
    state.set(State.CLOSED);
  }
*/

}
