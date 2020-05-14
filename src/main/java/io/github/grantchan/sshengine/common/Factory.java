package io.github.grantchan.sshengine.common;

/**
 * A simple interface used to create the other type of objects.
 *
 * <p>
 *   A {@code Factory} creates object without input parameter.<br/>
 *   For those objects require parameter to create, it is more appropriate to use a specific factory
 *   class.
 * </p>
 *
 * @param <T> the type of object that the factory creates
 */
@FunctionalInterface
public interface Factory<T> {

  /**
   * @return a new object
   */
  T create();
}
