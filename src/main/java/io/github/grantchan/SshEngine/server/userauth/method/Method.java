package io.github.grantchan.SshEngine.server.userauth.method;

import io.github.grantchan.SshEngine.server.ServerSession;
import io.netty.buffer.ByteBuf;

public interface Method {

  boolean authorize(String user, String service, ByteBuf buf, ServerSession session) throws Exception;
}
