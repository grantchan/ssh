package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.common.AbstractSession;

import java.util.Collection;
import java.util.stream.Collectors;

@FunctionalInterface
public interface SessionHolder {

  AbstractSession getSession();

  static <T extends SessionHolder>
  Collection<T> find(Collection<? extends T> range, AbstractSession session) {
    return range.stream().filter(e -> e.getSession() == session).collect(Collectors.toList());
  }
}
