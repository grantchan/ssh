package io.github.grantchan.ssh.handler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class IdexHandlerTest {

  private MyIdexHandler handler;

  @Before
  public void setUp() {
    handler = new MyIdexHandler();
  }

  @Test
  public void testGetIdSingleLine() {
    String val = "SSH-2.0-softwareversion\r\n";
    handler.setBuf(Unpooled.wrappedBuffer(val.getBytes(StandardCharsets.UTF_8)));
    String actual = handler.getClientId();
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test
  public void testGetIdSingleLineWithoutCR() {
    String id = "SSH-2.0-softwareversion\n";
    handler.setBuf(Unpooled.wrappedBuffer(id.getBytes(StandardCharsets.UTF_8)));
    String actual = handler.getClientId();
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test(expected = IllegalStateException.class)
  public void testGetIdContainsNullCharacter() {
    String val = "SSH-2.0-so" + '\0' + "ftwareversion\r\n";
    handler.setBuf(Unpooled.wrappedBuffer(val.getBytes(StandardCharsets.UTF_8)));
    handler.getClientId();
  }

  @Test
  public void testGetIdMultilines() {
    String id = "1st line\r\nSSH-2.0-softwareversion\r\n";
    handler.setBuf(Unpooled.wrappedBuffer(id.getBytes(StandardCharsets.UTF_8)));
    String actual = handler.getClientId();
    assertEquals("SSH-2.0-softwareversion", actual);
  }


  private class MyIdexHandler extends IdexHandler {
    void setBuf(ByteBuf buf) {
      this.accuBuf = buf;
    }
  }
}
