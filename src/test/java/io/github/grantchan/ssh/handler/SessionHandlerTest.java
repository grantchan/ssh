package io.github.grantchan.ssh.handler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class SessionHandlerTest {

  private MySessionHandler sessionHandler;

  @Before
  public void setUp() {
    sessionHandler = new MySessionHandler();
  }

  @Test
  public void testGetId() {
    ByteBuf id = Unpooled.wrappedBuffer("SSH-2.0-softwareversion\r\n".getBytes(StandardCharsets.UTF_8));
    String actual = sessionHandler.getId(id);
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test
  public void testGetIdWithoutCarrageReturn() {
    ByteBuf id = Unpooled.wrappedBuffer("SSH-2.0-softwareversion\n".getBytes(StandardCharsets.UTF_8));
    String actual = sessionHandler.getId(id);
    assertEquals("SSH-2.0-softwareversion", actual);
  }


  private class MySessionHandler extends SessionHandler {
    @Override
    protected String getId(ByteBuf buf) {
      return super.getId(buf);
    }
  }
}
