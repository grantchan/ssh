package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.digest.BuiltinDigestFactory;
import io.github.grantchan.ssh.trans.handler.DhgKexHandler;
import io.github.grantchan.ssh.trans.handler.KexHandler;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinKexHandlerFactory implements NamedObject, KexHandlerFactory {

  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public KexHandler create(Session session) {
      return new DhgKexHandler(BuiltinDigestFactory.sha1.create(), session);
    }
  },
  dhgexsha256("diffie-hellman-group-exchange-sha256") {
    @Override
    public KexHandler create(Session session) {
      return new DhgKexHandler(BuiltinDigestFactory.sha256.create(), session);
    }
  };

  public static final Set<BuiltinKexHandlerFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(BuiltinKexHandlerFactory.class));

  public String name;

  BuiltinKexHandlerFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static KexHandler create(String name, Session session) {
    BuiltinKexHandlerFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(session);
  }
}
