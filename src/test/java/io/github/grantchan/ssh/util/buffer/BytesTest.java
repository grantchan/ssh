package io.github.grantchan.ssh.util.buffer;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class BytesTest {

  @Test
  public void testLast() {
    byte[] a = {0x02, 0x01, 0x08, 0x05, 0x11, 0x03};
    assertArrayEquals(new byte[]{0x08, 0x05, 0x11, 0x03}, Bytes.last(a, 4));
  }
}