package io.github.grantchan.ssh.common.userauth.service;

import io.github.grantchan.ssh.client.userauth.ClientUserAuthService;
import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.server.userauth.service.ConnectionService;
import io.github.grantchan.ssh.server.userauth.service.ServerUserAuthService;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum ServiceFactories implements NamedObject, ServiceFactory {

  userauth("ssh-userauth") {
    @Override
    public Service create(Session session) {
      return session.isServer() ?
          new ServerUserAuthService(session) :
          new ClientUserAuthService(session);
    }
  },
  connection("ssh-connection") {
    @Override
    public Service create(Session session) {
      return new ConnectionService(session);
    }
  };

  public static final Set<ServiceFactories> values =
      Collections.unmodifiableSet(EnumSet.allOf(ServiceFactories.class));

  private final String name;

  ServiceFactories(String name) {
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
