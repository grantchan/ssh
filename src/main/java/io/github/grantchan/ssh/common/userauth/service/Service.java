package io.github.grantchan.ssh.common.userauth.service;

import io.netty.buffer.ByteBuf;

public interface Service {

  void handle(int cmd, ByteBuf req) throws Exception;
}
