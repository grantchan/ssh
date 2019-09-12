package io.github.grantchan.sshengine.server.userauth.method;

import io.github.grantchan.sshengine.server.ServerSession;
import io.netty.buffer.ByteBuf;

public interface Method {

  boolean authorize(String user, String service, ByteBuf buf, ServerSession session) throws Exception;
}
