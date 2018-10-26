package io.github.grantchan.ssh.userauth.service;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.userauth.handler.UserAuthService;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinServiceFactory implements NamedObject, ServiceFactory {

  userauth("ssh-userauth") {
    @Override
    public Service create(Session session) {
      return new UserAuthService(session);
    }
  },
  connection("ssh-connection") {
    @Override
    public Service create(Session session) {
      return null;
    }
  };

  public static final Set<BuiltinServiceFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(BuiltinServiceFactory.class));

  private final String name;

  BuiltinServiceFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static ServiceFactory from(String name) {
    return NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
  }

  public static Service create(String name, Session session) {
    ServiceFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(session);
  }
}
