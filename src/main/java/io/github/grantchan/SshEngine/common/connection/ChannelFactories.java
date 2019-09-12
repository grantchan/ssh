package io.github.grantchan.SshEngine.common.connection;

import io.github.grantchan.SshEngine.common.NamedObject;
import io.github.grantchan.SshEngine.common.Session;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum ChannelFactories implements NamedObject, ChannelFactory {

  SessionChannel("session") {
    @Override
    public Channel create(Session session) {
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
