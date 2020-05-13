package io.github.grantchan.sshengine.util;

import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;

public class LazySupplierTest {

  // the supplier to be tested
  private LazySupplier<String> ls;

  @Before
  public void setUp() {
    ls = new LazySupplier<String>() {
      @Override
      protected String initialize() {
        return "Hello";
      }
    };
  }

  /**
   * Test when get() is called multiple times, 10 in this case,
   * it should always return the same object.
   */
  @Test
  public void whenGetMutipleTimes_shouldReturnSameObject() {
    String str = ls.get();

    for (int i = 0; i < 10; i++) {
      assertEquals("Returned object is different.", str, ls.get());
    }
  }

  /**
   * Tests when get() is called from multiple thread, 30 in this case, concurrently,
   * it should always return the same object.
   */
  @Test
  public void whenGetFromDifferentThread_shouldReturnSameObject() {
    CountDownLatch latch = new CountDownLatch(1);

    int numOfThreads = 30;
    Thread[] threads = new Thread[numOfThreads];
    for (int i = 0; i < numOfThreads; i++) {
      Thread t = new Thread() {
        @Override
        public void run() {
          try {
            latch.await();
          } catch (InterruptedException e) {
            // ignore
          }

          setName(ls.get());  // use thread name to store the test object
        }
      };

      threads[i] = t;
      t.start();
    }

    latch.countDown();

    for (Thread t : threads) {
      try {
        t.join();
      } catch (InterruptedException e) {
        // ignore
      }
    }

    String str = ls.get();
    for (Thread t : threads) {
      assertEquals("Returned object is different.", str, t.getName());
    }
  }
}