package io.github.grantchan.SshEngine.common.transport.handler;

import io.github.grantchan.SshEngine.common.Session;

@FunctionalInterface
public interface SessionHolder {

  Session getSession();
}
