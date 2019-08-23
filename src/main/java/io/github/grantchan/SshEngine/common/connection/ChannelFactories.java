package io.github.grantchan.SshEngine.common.connection;

import io.github.grantchan.SshEngine.common.NamedFactory;
import io.github.grantchan.SshEngine.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum ChannelFactories implements NamedFactory<Channel> {

  Session("session") {
    @Override
    public Channel create() {
      return new SessionChannel();
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
