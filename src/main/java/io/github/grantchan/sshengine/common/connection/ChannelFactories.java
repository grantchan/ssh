package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum ChannelFactories implements NamedObject, ChannelFactory {

  SessionChannel("session") {
    @Override
    public Channel create(AbstractSession session) {
      return new SessionChannel(session);
    }
  };

  private static final Set<ChannelFactories> ALL =
      Collections.unmodifiableSet(EnumSet.allOf(ChannelFactories.class));

  private final String name;

  ChannelFactories(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return name;
  }

  public static ChannelFactories from(String name) {
    return NamedObject.find(name, ALL, String.CASE_INSENSITIVE_ORDER);
  }
}
