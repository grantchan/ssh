package io.github.grantchan.SshEngine.client.userauth.method;

import io.github.grantchan.SshEngine.common.NamedObject;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.stream.Collectors;

public enum KeyPairTypes implements NamedObject {

  RSA("RSA"),
  DSA("DSA");

  public static final Collection<KeyPairTypes> values =
      Collections.unmodifiableCollection(EnumSet.allOf(KeyPairTypes.class));

  public static final Collection<String> names =
      Collections.unmodifiableCollection(values.stream().map(KeyPairTypes::getName)
                                                        .collect(Collectors.toSet()));

  private final String name;

  KeyPairTypes(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return name;
  }
}
