package io.github.grantchan.ssh.userauth.method;

import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;

public interface Method {

  boolean authenticate(String user, ByteBuf buf, Session session) throws Exception;
}
