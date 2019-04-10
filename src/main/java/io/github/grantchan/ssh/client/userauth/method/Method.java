package io.github.grantchan.ssh.client.userauth.method;

import io.netty.buffer.ByteBuf;

public interface Method {

  boolean submit();

  boolean authenticate(ByteBuf buf);
}
