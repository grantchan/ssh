package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.handler.KexHandler;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum KexFactory implements NamedFactory<KexHandler> {

  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public KexHandler create(Object... params) throws Exception {
      return new KexHandler(DigestFactory.sha1.create());
    }
  },
  dhgexsha256("diffie-hellman-group-exchange-sha256") {
    @Override
    public KexHandler create(Object... params) throws Exception {
      return new KexHandler(DigestFactory.sha256.create());
    }
  };

  public static final Set<KexFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(KexFactory.class));

  public static String getNames() {
    return NamedObject.getNames(KexFactory.values);
  }

  public String name;

  KexFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

}
