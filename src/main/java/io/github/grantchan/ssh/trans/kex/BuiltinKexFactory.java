package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.NamedFactory;
import io.github.grantchan.ssh.trans.digest.BuiltinDigestFactory;
import io.github.grantchan.ssh.trans.handler.KexHandler;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinKexFactory implements NamedFactory<KexHandler> {

  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public KexHandler create() {
      return new KexHandler(BuiltinDigestFactory.sha1.create());
    }
  },
  dhgexsha256("diffie-hellman-group-exchange-sha256") {
    @Override
    public KexHandler create() {
      return new KexHandler(BuiltinDigestFactory.sha256.create());
    }
  };

  public static final Set<BuiltinKexFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(BuiltinKexFactory.class));

  public static String getNames() {
    return NamedObject.getNames(BuiltinKexFactory.values);
  }

  public String name;

  BuiltinKexFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

}
