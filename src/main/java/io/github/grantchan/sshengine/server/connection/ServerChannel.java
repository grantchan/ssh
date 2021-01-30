package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.CommonState;
import io.github.grantchan.sshengine.common.connection.Channel;
import io.netty.buffer.ByteBuf;

import java.io.IOException;

public interface ServerChannel extends Channel, CommonState {

  /**
   * Initialize the channel
   *
   * @param peerId Remote channel ID
   * @param rWndSize Remote window size
   * @param rPkSize Remote packet size
   */
  void init(int peerId, int rWndSize, int rPkSize);

  void handleWindowAdjust(ByteBuf req);

  void handleData(ByteBuf req) throws IOException;

  void handleRequest(ByteBuf req) throws IOException;
}
