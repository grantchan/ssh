package io.github.grantchan.ssh.client.transport.handler;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class CRequestHandlerTest {

  @Test
  public void testNegotiate() {
    assertEquals("c", new CRequestHandler(null).negotiate("a,b,c", "e,c"));
  }

  @Test
  public void testNegotiateWhenNothingInCommon() {
    assertNull(new CRequestHandler(null).negotiate("a,b,d", "e,c"));
  }
}