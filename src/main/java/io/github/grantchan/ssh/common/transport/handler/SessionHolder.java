package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.common.Session;

@FunctionalInterface
public interface SessionHolder {

  Session getSession();
}
