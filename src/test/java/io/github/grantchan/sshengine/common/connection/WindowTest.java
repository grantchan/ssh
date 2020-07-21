package io.github.grantchan.sshengine.common.connection;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.util.concurrent.TimeUnit;

public class WindowTest {

  private static final long SECONDS_TO_WAIT = 2;

  @Mock
  private Channel channel;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    Mockito.when(channel.getRemoteWindow()).thenReturn(new Window(channel, "server/remote"));
  }

  @Test
  public void whenWindowIsOutOfSpace_shouldThrowTimeoutExceptionAfterWait() throws Exception {
    try (Window wnd = channel.getRemoteWindow()) {
      wnd.consume(wnd.getSize());
      Assert.assertEquals("Window size is not empty", 0, wnd.getSize());

      long waitStart = System.currentTimeMillis();
      try {
        wnd.waitForSpace(1, TimeUnit.SECONDS.toMillis(SECONDS_TO_WAIT));
        Assert.fail("Not supposed to quit from waiting");
      } catch (WindowTimeoutException e) {
        long waitEnd = System.currentTimeMillis();
        long waitElapsed = TimeUnit.MILLISECONDS.toSeconds(waitEnd - waitStart);

        Assert.assertTrue("Wait time is not long enough, it's less than " + SECONDS_TO_WAIT,
            waitElapsed >= SECONDS_TO_WAIT);
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
}