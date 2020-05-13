package io.github.grantchan.sshengine.common.transport.kex;

import io.netty.buffer.ByteBuf;

import java.security.MessageDigest;

public interface KexGroup {

  MessageDigest getMd();

  Kex getKex();

  void handle(int cmd, ByteBuf req) throws Exception;
}
