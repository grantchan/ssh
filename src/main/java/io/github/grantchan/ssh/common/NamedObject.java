package io.github.grantchan.ssh.common;

import java.util.Collection;
import java.util.stream.Collectors;

public interface NamedObject {

  String getName();

  static String getNames(Collection<? extends NamedObject> objs) {
    return objs.stream().map(NamedObject::getName)
                        .collect(Collectors.joining(","));
  }
}
