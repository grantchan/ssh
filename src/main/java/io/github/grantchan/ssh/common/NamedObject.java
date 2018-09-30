package io.github.grantchan.ssh.common;

import io.netty.util.internal.StringUtil;

import java.util.Collection;
import java.util.Comparator;
import java.util.stream.Collectors;

public interface NamedObject {

  /**
   * @return the object name
   */
  String getName();

  /**
   * @param objects list of available resources
   * @return a comma separated list of names
   */
  static String getNames(Collection<? extends NamedObject> objects) {
    return objects.stream().map(NamedObject::getName)
                        .collect(Collectors.joining(","));
  }

  /**
   * @param <T>       The generic object type
   * @param name      Name of the object - ignored if {@code null}/empty
   * @param factories The {@link NamedObject} to check - ignore if {@code null}/empty
   * @param c         The {@link Comparator} to decide whether the {@link NamedObject#getName()}
   *                  matches the <tt>name</tt> parameter
   * @return          The <U>first</U> object whose name matches the parameter (by invoking
   * {@link Comparator#compare(Object, Object)} - {@code null} if no match found
   */
  static <T extends NamedObject>
  T find(String name, Collection<? extends T> factories, Comparator<String> c) {
    return StringUtil.isNullOrEmpty(name) ? null :
        factories.stream().filter(f -> c.compare(f.getName(), name) == 0).findFirst().orElse(null);
  }
}
