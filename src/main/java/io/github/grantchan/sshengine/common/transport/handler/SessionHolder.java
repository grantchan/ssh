package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.common.AbstractSession;

@FunctionalInterface
public interface SessionHolder {

  AbstractSession getSession();
}
