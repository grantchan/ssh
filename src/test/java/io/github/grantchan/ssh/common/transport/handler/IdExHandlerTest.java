package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.server.handler.SIdExHandler;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class IdExHandlerTest {

  private MyIdExHandler handler;

  @Before
  public void setUp() {
    handler = new MyIdExHandler();
  }

  @Test
  public void testGetIdSingleLine() {
    String val = "SSH-2.0-softwareversion\r\n";
    handler.setBuf(Unpooled.wrappedBuffer(val.getBytes(StandardCharsets.UTF_8)));
    String actual = handler.getId();
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test
  public void testGetIdSingleLineWithoutCR() {
    String id = "SSH-2.0-softwareversion\n";
    handler.setBuf(Unpooled.wrappedBuffer(id.getBytes(StandardCharsets.UTF_8)));
    String actual = handler.getId();
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test(expected = IllegalStateException.class)
  public void testGetIdContainsNullCharacter() {
    String val = "SSH-2.0-so" + '\0' + "ftwareversion\r\n";
    handler.setBuf(Unpooled.wrappedBuffer(val.getBytes(StandardCharsets.UTF_8)));
    handler.getId();
  }

  @Test
  public void testGetIdMultilines() {
    String id = "1st line\r\nSSH-2.0-softwareversion\r\n";
    handler.setBuf(Unpooled.wrappedBuffer(id.getBytes(StandardCharsets.UTF_8)));
    String actual = handler.getId();
    assertEquals("SSH-2.0-softwareversion", actual);
  }


  private class MyIdExHandler extends SIdExHandler {
    void setBuf(ByteBuf buf) {
      this.accuBuf = buf;
    }
  }
}
