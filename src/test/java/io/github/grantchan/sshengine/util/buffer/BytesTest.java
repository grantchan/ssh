package io.github.grantchan.sshengine.util.buffer;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BytesTest {

  @Test
  public void testFrom_whenBooleansToConcatenate() {
    byte[] expected = {
        (byte) 0x01, (byte) 0x00, (byte) 0x00
    };

    assertArrayEquals(expected, Bytes.concat(Bytes.toArray(true),
                                             Bytes.toArray(false),
                                             Bytes.toArray(false)));
  }

  @Test
  public void testBigEndianFrom_whenIntegersToConcatenate() {
    int a = 0x305, b = 0x9, c = 0xF2, d = 0xAE6;

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x05,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xF2,
        (byte) 0x00, (byte) 0x00, (byte) 0x0A, (byte) 0xE6
    };

    assertArrayEquals(expected, Bytes.concat(Bytes.toBigEndian(a, b, c, d)));
  }

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
  public void testBigEndianFrom_forBigInteger() {
    byte[] expected = {(byte) 0x79, (byte) 0x34, (byte) 0x7F, (byte) 0x50};

    assertArrayEquals(expected, Bytes.toBigEndian(0x79347F50));
  }

  @Test
  public void testBigEndianTo_whenByteArrayIsLessThan4Bytes() {
    byte[] input = {(byte) 0x11, (byte) 0xA2, (byte) 0x33, (byte) 0x2F};

    assertEquals(0x11A2332F, Bytes.readBigEndian(input));
  }

  @Test
  public void testBigEndianTo_whenByteArrayIsLongerThan4Bytes() {
    byte[] input = {(byte) 0x11, (byte) 0xA2, (byte) 0x33, (byte) 0x2F, (byte) 0x06, (byte) 0x59};

    assertEquals(0x11A2332F, Bytes.readBigEndian(input));
  }

  @Test
  public void testJoin_whenAllParametersAreNotNull() {
    byte[] a = {(byte) 0x01, (byte) 0x02, (byte) 0x06};
    byte[] b = {(byte) 0x05, (byte) 0x08};

    assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x06, (byte) 0x05, (byte) 0x08},
                      Bytes.concat(a, b));
  }

  @Test
  public void testJoin_whenOneOfArgumentIsNull() {
    byte[] a = {(byte) 0x08, (byte) 0x02};
    byte[] b = {(byte) 0x11};

    assertArrayEquals(new byte[]{(byte) 0x08, (byte) 0x02, (byte) 0x011}, Bytes.concat(a, null, b));
  }

  @Test
  public void testJoinByteArraysToLengthByteArray() {
    byte[] a = {(byte) 0x1A, (byte) 0xEB, (byte) 0xFA, (byte) 0x66};
    byte[] b = {(byte) 0x29, (byte) 0x8F};

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04,
        (byte) 0x1A, (byte) 0xEB, (byte) 0xFA, (byte) 0x66,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02,
        (byte) 0x29, (byte) 0x8F
    };

    assertArrayEquals(expected, Bytes.join(Bytes.SEPARATE_BY_LENGTH, a, b));
    assertArrayEquals(expected, Bytes.join(Bytes.SEPARATE_BY_LENGTH, a, null, b));
    assertArrayEquals(expected, Bytes.join(Bytes.SEPARATE_BY_LENGTH, null, a, b));
    assertArrayEquals(expected, Bytes.join(Bytes.SEPARATE_BY_LENGTH, a, b, null));
  }

  @Test
  public void testJoinStringByteArraysToLengthByteArray() {
    byte[] a = "12345678".getBytes(StandardCharsets.UTF_8);
    byte[] b = " abcdefghijklmnopq".getBytes(StandardCharsets.UTF_8);

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08,
        (byte) '1',  (byte) '2',  (byte) '3',  (byte) '4',
        (byte) '5',  (byte) '6',  (byte) '7',  (byte) '8',
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x12,
        (byte) ' ',  (byte) 'a',  (byte) 'b',  (byte) 'c',
        (byte) 'd',  (byte) 'e',  (byte) 'f',  (byte) 'g',
        (byte) 'h',  (byte) 'i',  (byte) 'j',  (byte) 'k',
        (byte) 'l',  (byte) 'm',  (byte) 'n',  (byte) 'o',
        (byte) 'p',  (byte) 'q'
     };

    assertArrayEquals(Bytes.join(Bytes.SEPARATE_BY_LENGTH, a, b), expected);
  }

  @Test
  public void testJoinStringsToLengthByteArray() {
    String a = "334%90$00123";
    String b = "cpp&java";

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0C,
        (byte) '3', (byte) '3', (byte) '4', (byte) '%',
        (byte) '9', (byte) '0', (byte) '$', (byte) '0',
        (byte) '0', (byte) '1', (byte) '2', (byte) '3',
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08,
        (byte) 'c', (byte) 'p', (byte) 'p', (byte) '&',
        (byte) 'j', (byte) 'a', (byte) 'v', (byte) 'a'
    };

    assertArrayEquals(expected, Bytes.join(
                                  Bytes.SEPARATE_BY_LENGTH,
                                  a.getBytes(StandardCharsets.UTF_8),
                                  b.getBytes(StandardCharsets.UTF_8)
                                ));

    assertArrayEquals(expected, Bytes.join(
                                  Bytes.SEPARATE_BY_LENGTH,
                                  a.getBytes(StandardCharsets.UTF_8),
                                  null,
                                  b.getBytes(StandardCharsets.UTF_8)
                                ));
    assertArrayEquals(expected, Bytes.join(
                                  Bytes.SEPARATE_BY_LENGTH,
                                  null,
                                  a.getBytes(StandardCharsets.UTF_8),
                                  b.getBytes(StandardCharsets.UTF_8)
                                ));
    assertArrayEquals(expected, Bytes.join(
                                  Bytes.SEPARATE_BY_LENGTH,
                                  a.getBytes(StandardCharsets.UTF_8),
                                  b.getBytes(StandardCharsets.UTF_8),
                                  null,
                                  null
                                ));
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