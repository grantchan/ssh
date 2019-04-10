package io.github.grantchan.ssh.client.userauth.method;

import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface Method {

  boolean submit();

  boolean authenticate(ByteBuf buf) throws GeneralSecurityException, IOException;
}
