package io.github.grantchan.sshengine.common.userauth.service;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.connection.service.ClientConnectionService;
import io.github.grantchan.sshengine.client.userauth.service.ClientUserAuthService;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.NamedObject;
import io.github.grantchan.sshengine.common.Service;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.server.connection.service.ServerConnectionService;
import io.github.grantchan.sshengine.server.userauth.service.ServerUserAuthService;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum ServiceFactories implements NamedObject, ServiceFactory {

  userauth("ssh-userauth") {
    @Override
    public Service create(AbstractSession session) {
      return session instanceof ServerSession ?
          new ServerUserAuthService((ServerSession)session) :
          new ClientUserAuthService((ClientSession)session);
    }
  },
  connection("ssh-connection") {
    @Override
    public Service create(AbstractSession session) {
      return session instanceof ServerSession ?
          new ServerConnectionService((ServerSession) session) :
          new ClientConnectionService((ClientSession) session);
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

  public static Service create(String name, AbstractSession session) {
    ServiceFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(session);
  }
}
