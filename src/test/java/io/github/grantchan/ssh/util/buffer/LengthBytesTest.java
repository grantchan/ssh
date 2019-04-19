package io.github.grantchan.ssh.util.buffer;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;

public class LengthBytesTest {

  @Test
  public void testConcat2ByteArraysToALengthByteArray() {
    byte[] v_c = "SSH-2.0-Client_0.70".getBytes(StandardCharsets.UTF_8);
    byte[] v_s = "SSH-2.0-Server".getBytes(StandardCharsets.UTF_8);

    byte[] expected = {(byte) 0, (byte) 0, (byte) 0, (byte) 19, (byte) 83, (byte) 83, (byte) 72,
                       (byte) 45, (byte) 50, (byte) 46, (byte) 48, (byte) 45, (byte) 67, (byte) 108,
                       (byte) 105, (byte) 101, (byte) 110, (byte) 116, (byte) 95, (byte) 48,
                       (byte) 46, (byte) 55, (byte) 48, (byte) 0, (byte) 0, (byte) 0, (byte) 14,
                       (byte) 83, (byte) 83, (byte) 72, (byte) 45, (byte) 50, (byte) 46, (byte) 48,
                       (byte) 45, (byte) 83, (byte) 101, (byte) 114, (byte) 118, (byte) 101,
                       (byte) 114};

    assertArrayEquals(expected, LengthBytes.concat(v_c, v_s));
  }
}