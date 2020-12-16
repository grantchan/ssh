package io.github.grantchan.sshengine.common.connection;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class WindowTest {

  @Mock
  private AbstractChannel channel;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    Mockito.when(channel.getRemoteWindow()).thenReturn(new Window(channel, "server/remote"));
  }

  @Test
  public void whenWindowIsOutOfSpace_shouldThrowTimeoutExceptionAfterWait() throws Exception {
    final long secondsToWait = 2;

    try (Window wnd = channel.getRemoteWindow()) {
      wnd.consume(wnd.getSize());
      Assert.assertEquals("Window size is not empty", 0, wnd.getSize());

      long waitStart = System.currentTimeMillis();
      try {
        wnd.waitForSpace(1, TimeUnit.SECONDS.toMillis(secondsToWait));
        Assert.fail("Not supposed to quit from waiting");
      } catch (WindowTimeoutException e) {
        long waitEnd = System.currentTimeMillis();
        long waitElapsed = TimeUnit.MILLISECONDS.toSeconds(waitEnd - waitStart);

        Assert.assertTrue("Wait time is not long enough, it's less than " + secondsToWait,
            waitElapsed >= secondsToWait);
      }

      wnd.close();
      Assert.assertFalse("Window isn't closed", wnd.isOpen());

      try {
        wnd.waitForSpace(1, TimeUnit.MILLISECONDS.toMillis(1));
      } catch (WindowClosedException e) {
        // ignore
      }
    }
  }

  @Test
  public void afterWaitForSpaceAndExpandedByOtherThreads_shouldWakeAndReturnOnceTargetReached()
      throws Exception {

    final long secondsToWait = 10;

    final int bytesToWaitFor = 100;
    final int threadsToExpand = 34;
    final int bytesToExpand = 3;

    try (Window wnd = channel.getRemoteWindow()) {
      wnd.consume(wnd.getSize());
      Assert.assertEquals("Window size is not empty", 0, wnd.getSize());

      // A thread waiting for some space
      Thread waitThread = new Thread(() -> {
        try {
          wnd.waitForSpace(bytesToWaitFor, TimeUnit.SECONDS.toMillis(secondsToWait));
        } catch (InterruptedException e) {
          // ignore
        } catch (WindowClosedException e) {
          Assert.fail("Window should not be closed");
        } catch (WindowTimeoutException e) {
          Assert.fail("Waiting too long for space to free up");
        }
      });
      waitThread.start();

      // use a latch to start below threads simultaneously
      CountDownLatch latch = new CountDownLatch(1);

      // create a handful of threads to expand the window
      Thread[] producers = new Thread[threadsToExpand];
      for (int i = 0; i < threadsToExpand; i++) {
        producers[i] = new Thread(() -> {
          try {
            latch.await();
          } catch (InterruptedException e) {
            e.printStackTrace();
          }
          wnd.expand(bytesToExpand);
        });
        producers[i].start();
      }

      // release threads
      latch.countDown();

      // wait for the expansion process to complete
      for (Thread t : producers) {
        t.join();
      }

      // wait for the wait thread to complete
      waitThread.join();

      Assert.assertEquals(threadsToExpand * bytesToExpand, wnd.getSize());
    }
  }
}