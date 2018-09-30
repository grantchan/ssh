package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.Service;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum ServiceFactory implements NamedFactory<Service> {

  userauth("ssh-userauth") {
    @Override
    public Service create(Object... params) throws Exception {
      return null;
    }
  },
  connection("ssh-connection") {
    @Override
    public Service create(Object... params) throws Exception {
      return null;
    }
  };

  public static final Set<ServiceFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(ServiceFactory.class));

  private final String name;

  ServiceFactory(String name) {
    this.name = name;
  }

  @Override
  public Service create(Object... params) throws Exception {
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
