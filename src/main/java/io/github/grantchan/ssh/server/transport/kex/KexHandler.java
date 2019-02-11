package io.github.grantchan.ssh.server.transport.kex;

import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.kex.KeyExchange;
import io.netty.buffer.ByteBuf;

import java.security.MessageDigest;

public interface KexHandler {

  MessageDigest getMd();

  KeyExchange getKex();

  void handleMessage(int cmd, ByteBuf req) throws SshException;
}
