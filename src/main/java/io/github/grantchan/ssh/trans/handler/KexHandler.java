package io.github.grantchan.ssh.trans.handler;

import io.netty.buffer.ByteBuf;

import java.io.IOException;

public interface KexHandler {

  void handleMessage(int cmd, ByteBuf req) throws IOException;

  void handleNewKeys(ByteBuf req);
}
