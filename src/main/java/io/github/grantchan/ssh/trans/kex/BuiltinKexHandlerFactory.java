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
    public KexHandler create(Session s) {
      return new DhGroupExHandler(BuiltinDigestFactory.sha256.create(), s);
    }
  },
  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupExHandler(BuiltinDigestFactory.sha1.create(), s);
    }
  },

  dhg18sha512("diffie-hellman-group18-sha512") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha512.create(), new DH(DhGroup.P18), s);
    }
  },
  dhg17sha512("diffie-hellman-group17-sha512") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha512.create(), new DH(DhGroup.P17), s);
    }
  },
  dhg16sha512("diffie-hellman-group16-sha512") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha512.create(), new DH(DhGroup.P16), s);
    }
  },
  dhg15sha512("diffie-hellman-group15-sha512") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha512.create(), new DH(DhGroup.P15), s);
    }
  },
  dhg14sha256("diffie-hellman-group14-sha256") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha256.create(), new DH(DhGroup.P14), s);
    }
  },
  
  /* legacy diffie hellman key exchanges */
  dhg14sha1("diffie-hellman-group14-sha1") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha1.create(), new DH(DhGroup.P14), s);
    }
  },
  dhg1sha1("diffie-hellman-group1-sha1") {
    @Override
    public KexHandler create(Session s) {
      return new DhGroupHandler(BuiltinDigestFactory.sha1.create(), new DH(DhGroup.P1), s);
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

  public static KexHandler create(String name, Session s) {
    BuiltinKexHandlerFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(s);
  }
}
