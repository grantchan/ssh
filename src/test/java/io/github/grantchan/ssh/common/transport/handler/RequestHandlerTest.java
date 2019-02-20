package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.common.Session;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mock;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.MockitoAnnotations.initMocks;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RequestHandlerTest {

  @Mock
  private Session session;

  private RequestHandler handler;

  @Before
  public void setUp() {
    initMocks(this);

    handler = new RequestHandler(session);
  }
  @Test
  public void testNegotiateNormalCase() {
    assertEquals("c", handler.negotiate("a,b,c", "e,c"));
  }

  @Test
  public void testNegotiateWhenNothingInCommon() {
    assertNull(handler.negotiate("a,b,d", "e,c"));
  }

  @Test
  public void whenNamesHaveSamePrefix_shouldBeAbleToDistinguish() {
    assertNull(handler.negotiate("a,b,c", "c1,d"));
  }
}