package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.Service;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SshServiceFactory implements NamedFactory<Service> {

  userauth("ssh-userauth") {
    @Override
    public Service create() {
      return null;
    }
  },
  connection("ssh-connection") {
    @Override
    public Service create() {
      return null;
    }
  };

  public static final Set<SshServiceFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SshServiceFactory.class));

  private final String name;

  SshServiceFactory(String name) {
    this.name = name;
  }

  @Override
  public Service create() {
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
