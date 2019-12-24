package io.github.grantchan.sshengine.util;

import java.util.function.Supplier;

/**
 * A supplier class implements lazy initialization pattern.
 *
 * <p></p>
 *
 * This abstract base class provides an implementation of the double-check idiom for an instance
 * field as discussed in Joshua Bloch's "Effective Java", 2nd edition, item 71.
 *
 * <p></p>
 *
 * The class already implements all necessary synchronization.
 *
 * <p></p>
 *
 * A concrete subclass has to implement the {@code initialize()} method, which actually creates the
 * wrapped data object.
 *
 * <p></p>
 *
 * If multiple threads call the {@code get()} method when the object has not yet been created, they
 * are blocked until initialization completes, it's guaranteed that only one single instance of the
 * wrapped object class is created, which will be used by all callers.
 *
 * <p></p>
 *
 * Once initialized, calls to the {@code get()} method are fast since no synchronization is needed
 * (only an access to a <b>volatile</b> member field).
 *
 * <p></p>
 *
 * @param <T> the type of the object managed by this initializer class
 */
public abstract class LazySupplier<T> implements Supplier<T> {

  private static final Object NOT_INITIALIZED = new Object();

  @SuppressWarnings("unchecked")
  private volatile T object = (T) NOT_INITIALIZED;

  /**
   * Returns the object wrapped by this instance.
   *
   * <p></p>
   *
   * The object is created on first access, after that it is cached.
   *
   * @return the object initialized by this {@code LazySupplier} object
   */
  @Override
  public T get() {

    T result = object;

    if (result == NOT_INITIALIZED) {
      synchronized (this) {
        result = object;
        if (result == NOT_INITIALIZED) {
          object = result = initialize();
        }
      }
    }

    return result;
  }

  /**
   * Creates and initializes the object managed by this {@code LazySupplier}.
   *
   * <p></p>
   *
   * This method is called by {@link #get()} when the object is accessed for the first time.
   *
   * <p></p>
   *
   * An implementation can focus on the creation of the object, no synchronization is needed, as
   * it's already handled by {@code get()}.
   *
   * @return the managed data object
   */
  protected abstract T initialize();
}
