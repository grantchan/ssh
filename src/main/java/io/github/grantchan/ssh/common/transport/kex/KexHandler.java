package io.github.grantchan.ssh.common.transport.kex;

import io.netty.buffer.ByteBuf;

import java.security.MessageDigest;

public interface KexHandler {

  MessageDigest getMd();

  KeyExchange getKex();

  void handle(int cmd, ByteBuf req) throws Exception;
}
