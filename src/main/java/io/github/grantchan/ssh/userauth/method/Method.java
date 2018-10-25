package io.github.grantchan.ssh.userauth.method;

import io.netty.buffer.ByteBuf;

public interface Method {

  boolean authenticate(String user, String service, ByteBuf buf) throws Exception;
}
