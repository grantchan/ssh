package io.github.grantchan.ssh.server.userauth.method;

import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;

public interface Method {

  boolean authenticate(String user, String service, ByteBuf buf, Session session) throws Exception;
}
