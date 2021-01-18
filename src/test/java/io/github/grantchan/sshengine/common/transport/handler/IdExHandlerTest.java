package io.github.grantchan.sshengine.common.transport.handler;

import io.netty.buffer.Unpooled;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class IdExHandlerTest {

  private final Charset utf8 = StandardCharsets.UTF_8;

  @Test
  public void testGetIdSingleLine() {
    String val = "SSH-2.0-softwareversion\r\n";
    String actual = IdExHandler.getId(Unpooled.wrappedBuffer(val.getBytes(utf8)));
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test
  public void testGetIdSingleLineWithoutCR() {
    String id = "SSH-2.0-softwareversion\n";
    String actual = IdExHandler.getId(Unpooled.wrappedBuffer(id.getBytes(utf8)));
    assertEquals("SSH-2.0-softwareversion", actual);
  }

  @Test
  public void testGetIdContainsNullCharacter() {
    String val = "SSH-2.0-so" + '\0' + "ftwareversion\r\n";
    IllegalStateException thrown =
        assertThrows(IllegalStateException.class, () -> {
          IdExHandler.getId(Unpooled.wrappedBuffer(val.getBytes(utf8)));
        });

    assertNotNull(thrown.getMessage());
    assertTrue(thrown.getMessage().contains("character #" + (val.indexOf('\0') + 1)));
  }

  @Test
  public void testGetIdMultilines() {
    String id = "1st line\r\nSSH-2.0-softwareversion\r\n";
    String actual = IdExHandler.getId(Unpooled.wrappedBuffer(id.getBytes(utf8)));
    assertEquals("SSH-2.0-softwareversion", actual);
  }
}
