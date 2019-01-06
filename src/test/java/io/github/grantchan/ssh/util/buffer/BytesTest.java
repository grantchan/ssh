package io.github.grantchan.ssh.util.buffer;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BytesTest {

  @Test
  public void testConcat_normal() {
    byte[] a = {0x01, 0x02, 0x06};
    byte[] b = {0x05, 0x08};
    assertArrayEquals(new byte[]{0x01, 0x02, 0x06, 0x05, 0x08}, Bytes.concat(a, b));
  }

  @Test
  public void testConcat_whenOneOfArgumentIsNull() {
    byte[] a = {0x08, 0x02};
    byte[] b = {0x11};
    assertArrayEquals(new byte[]{0x08, 0x02, 0x011}, Bytes.concat(a, null, b));
  }

  @Test
  public void testConcat_whenAllArgumentsAreNull() {
    assertNull(Bytes.concat(null, null, null));
  }

  @Test
  public void testLast() {
    byte[] a = {0x02, 0x01, 0x08, 0x05, 0x11, 0x03};
    assertArrayEquals(new byte[]{0x08, 0x05, 0x11, 0x03}, Bytes.last(a, 4));
  }
}