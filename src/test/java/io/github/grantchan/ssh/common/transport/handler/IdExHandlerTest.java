package io.github.grantchan.ssh.common.transport.handler;

import io.netty.buffer.Unpooled;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class IdExHandlerTest {

  @Test
  public void testGetIdSingleLine() {
    String val = "SSH-2.0-softwareversion\r\n";
    String actual = IdExHandler.getId(Unpooled.wrappedBuffer(val.getBytes(StandardCharsets.UTF_8)));
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test
  public void testGetIdSingleLineWithoutCR() {
    String id = "SSH-2.0-softwareversion\n";
    String actual = IdExHandler.getId(Unpooled.wrappedBuffer(id.getBytes(StandardCharsets.UTF_8)));
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test(expected = IllegalStateException.class)
  public void testGetIdContainsNullCharacter() {
    String val = "SSH-2.0-so" + '\0' + "ftwareversion\r\n";
    IdExHandler.getId(Unpooled.wrappedBuffer(val.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void testGetIdMultilines() {
    String id = "1st line\r\nSSH-2.0-softwareversion\r\n";
    String actual = IdExHandler.getId(Unpooled.wrappedBuffer(id.getBytes(StandardCharsets.UTF_8)));
    assertEquals("SSH-2.0-softwareversion", actual);
  }
}
