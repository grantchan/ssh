package io.github.grantchan.ssh.common;

import io.netty.util.internal.StringUtil;

import java.util.Collection;

public interface Factory<T> {

  T create() throws Exception;

  static <T, U extends NamedObject & Factory<T>>
  T create(Collection<? extends U> factories, String name) throws Exception {
    if (!StringUtil.isNullOrEmpty(name)) {
      for (U f : factories) {
        if (name.equalsIgnoreCase(f.getName())) {
          return f.create();
        }
      }
    }
    return null;
  }
}
