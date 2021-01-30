package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.common.CommonState;
import io.github.grantchan.sshengine.common.connection.Channel;
import io.netty.buffer.ByteBuf;

public interface ClientChannel extends Channel, CommonState {

  /**
   * Returns the type of this channel, it could be a shell, a system command, or built-in subsystem
   *
   * @return "shell" or "exec" or "subsystem"
   */
  String getType();

  void handleOpenConfirmation(ByteBuf req);

  void handleOpenFailure(ByteBuf req);
}
