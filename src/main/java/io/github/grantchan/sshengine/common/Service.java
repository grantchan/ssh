package io.github.grantchan.sshengine.common;

import io.netty.buffer.ByteBuf;

@FunctionalInterface
public interface Service {

  void handle(int cmd, ByteBuf req) throws Exception;
}
