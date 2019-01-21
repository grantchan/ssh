package io.github.grantchan.ssh.server.transport.handler;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SRequestHandlerTest {

  @Test
  public void testNegotiate() {
    assertEquals("c", new SRequestHandler(null).negotiate("a,b,c,d", "c,e"));
  }

  @Test
  public void testNegotiateWhenNothingInCommon() {
    assertNull(new SRequestHandler(null).negotiate("a,b,d", "e,c"));
  }
}