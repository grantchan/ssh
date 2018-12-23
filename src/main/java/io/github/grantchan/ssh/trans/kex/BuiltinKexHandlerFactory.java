package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.digest.BuiltinDigestFactory;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinKexHandlerFactory implements NamedObject, KexHandlerFactory {

  dhgexsha256("diffie-hellman-group-exchange-sha256") {
    @Override
    public KexHandler create(Session session) {
      return new DhgKexHandler(BuiltinDigestFactory.sha256.create(), session);
    }
  },
  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public KexHandler create(Session session) {
      return new DhgKexHandler(BuiltinDigestFactory.sha1.create(), session);
    }
  },

  /* legacy diffie hellman key exchanges */
  dhg18sha512("diffie-hellman-group18-sha512") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha512.create(), DHGroupData.P18, session);
    }
  },
  dhg17sha512("diffie-hellman-group17-sha512") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha512.create(), DHGroupData.P17, session);
    }
  },
  dhg16sha512("diffie-hellman-group16-sha512") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha512.create(), DHGroupData.P16, session);
    }
  },
  dhg15sha512("diffie-hellman-group15-sha512") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha512.create(), DHGroupData.P15, session);
    }
  },
  dhg14sha256("diffie-hellman-group14-sha256") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha256.create(), DHGroupData.P14, session);
    }
  },
  dhg14sha1("diffie-hellman-group14-sha1") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha1.create(), DHGroupData.P14, session);
    }
  },
  dhg1sha1("diffie-hellman-group1-sha1") {
    @Override
    public KexHandler create(Session session) {
      return new DhKexHandler(BuiltinDigestFactory.sha1.create(), DHGroupData.P1, session);
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
