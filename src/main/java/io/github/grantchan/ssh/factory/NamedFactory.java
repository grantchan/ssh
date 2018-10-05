package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collection;

public interface NamedFactory<T> extends NamedObject, Factory<T> {

  /**
   * @param <T>       type of object to create
   * @param name      the factory name to use
   * @param factories list of available factories
   * @param params    parameters to create the object
   * @return          a newly created object or {@code null} if the factory is not in the list
   */
  static <T>
  T create(Collection<? extends NamedFactory<? extends T>> factories, String name, Object... params)
      throws Exception {
    NamedFactory<? extends T> f = NamedObject.find(name, factories, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create();
  }
}
