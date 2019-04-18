package io.github.grantchan.ssh.util.buffer;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BytesTest {

  @Test
  public void testResize_whenNewSizeIsSmallerThanOldSize() {
    byte[] input = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
    byte[] expected = {(byte) 0x01, (byte) 0x02, (byte) 0x03};

    assertArrayEquals(expected, Bytes.resize(input, 3));
  }

  @Test
  public void testResize_whenNewSizeIsBiggerThanOldSize() {
    byte[] input = {(byte) 0x02, (byte) 0x04, (byte) 0x09, (byte) 0x06, (byte) 0x08};
    byte[] expected = {(byte) 0x02, (byte) 0x04, (byte) 0x09, (byte) 0x06, (byte) 0x08};

    assertArrayEquals(expected, Bytes.resize(input, 10));
  }

  @Test
  public void testHtonl_forBigInteger() {
    byte[] expected = {(byte) 0x79, (byte) 0x34, (byte) 0x7F, (byte) 0x50};

    assertArrayEquals(expected, Bytes.htonl(0x79347F50));
  }

  @Test
  public void testNl_whenByteArrayIsLessThan4Bytes() {
    byte[] input = {(byte) 0x11, (byte) 0xA2, (byte) 0x33, (byte) 0x2F};

    assertEquals(0x11A2332F, Bytes.nl(input));
  }

  @Test
  public void testNl_whenByteArrayIsLongerThan4Bytes() {
    byte[] input = {(byte) 0x11, (byte) 0xA2, (byte) 0x33, (byte) 0x2F, (byte) 0x06, (byte) 0x59};

    assertEquals(0x11A2332F, Bytes.nl(input));
  }

  @Test
  public void testConcat_whenAllParametersAreNotNull() {
    byte[] a = {(byte) 0x01, (byte) 0x02, (byte) 0x06};
    byte[] b = {(byte) 0x05, (byte) 0x08};

    assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x06, (byte) 0x05, (byte) 0x08},
                      Bytes.concat(a, b));
  }

  @Test
  public void testConcat_whenOneOfArgumentIsNull() {
    byte[] a = {(byte) 0x08, (byte) 0x02};
    byte[] b = {(byte) 0x11};

    assertArrayEquals(new byte[]{(byte) 0x08, (byte) 0x02, (byte) 0x011}, Bytes.concat(a, null, b));
  }

  @Test
  public void testConcat_whenAllArgumentsAreNull() {
    assertNull(Bytes.concat(null, null, null));
  }

  @Test
  public void testLast_whenGettingShorterThanTheLengthOfArray() {
    byte[] input = {(byte) 0x02, (byte) 0x01, (byte) 0x08, (byte) 0x05, (byte) 0x11, (byte) 0x03};
    byte[] expected = {(byte) 0x08, (byte) 0x05, (byte) 0x11, (byte) 0x03};

    assertArrayEquals(expected, Bytes.last(input, 4));
  }

  @Test
  public void testLast_whenGettingLongerThanTheLengthOfArray() {
    byte[] input = {(byte) 0x02, (byte) 0x01, (byte) 0x08, (byte) 0x05, (byte) 0x11, (byte) 0x03};
    byte[] expected = {(byte) 0x02, (byte) 0x01, (byte) 0x08, (byte) 0x05, (byte) 0x11, (byte) 0x03};

    assertArrayEquals(expected, Bytes.last(input, 9));
  }

  @Test
  public void testLast_whenGettingNegativeNumberOfBytesFromArray() {
    byte[] input = {(byte) 0x02, (byte) 0x01, (byte) 0x08, (byte) 0x05, (byte) 0x11, (byte) 0x03};

    assertNull(Bytes.last(input, -5));
  }
  
  @Test
  public void testHex() {
    byte[] input = {(byte) 0xB2, (byte) 0x5F, (byte) 0x08, (byte) 0x05, (byte) 0x11, (byte) 0x03};

    assertEquals("b2:5f:08:05:11:03", Bytes.hex(input));
  }

}