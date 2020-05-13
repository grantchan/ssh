package io.github.grantchan.sshengine.common.transport.handler;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ReqHandlerTest {

  @Test
  public void testNegotiateNormalCase() {
    assertEquals("c", ReqHandler.negotiate("a,b,c", "e,c"));
  }

  @Test
  public void testNegotiateWhenNothingInCommon() {
    assertNull(ReqHandler.negotiate("a,b,d", "e,c"));
  }

  @Test
  public void whenNamesHaveSamePrefix_shouldBeAbleToDistinguish() {
    assertNull(ReqHandler.negotiate("a,b,c", "c1,d"));
  }
}