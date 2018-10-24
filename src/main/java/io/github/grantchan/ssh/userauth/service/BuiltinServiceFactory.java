package io.github.grantchan.ssh.userauth.service;

import io.github.grantchan.ssh.common.NamedFactory;
import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.kex.BuiltinKexHandlerFactory;
import io.github.grantchan.ssh.userauth.handler.UserAuthService;
import io.netty.util.internal.StringUtil;

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
  public Service create(Session session) {
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static BuiltinServiceFactory fromName(String name) {
    if (StringUtil.isNullOrEmpty(name)) {
      return null;
    }

    for (BuiltinServiceFactory f : values) {
      if (name.equalsIgnoreCase(f.getName())) {
        return f;
      }
    }
    return null;
  }
}
