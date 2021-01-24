package io.github.grantchan.sshengine.util.buffer;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.math.BigInteger;
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

    assertArrayEquals(expected, Bytes.toBytes(0x79347F50));
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
  public void testJoinBigInteger() {
    byte[] expected = {
        (byte) 0, (byte) 0, (byte) 0, (byte) 1,

        (byte) 1,

        (byte) 0, (byte) 0, (byte) 0, (byte) 1,

        (byte) 0
    };

    assertArrayEquals(expected, Bytes.joinWithLength(BigInteger.ONE, BigInteger.ZERO));

    expected = new byte[] {
        (byte) 0, (byte) 0, (byte) 0, (byte) 27,

        (byte) 4, (byte) 94, (byte) -75, (byte) 10, (byte) 8, (byte) 3, (byte) 2, (byte) 21,
        (byte) -18, (byte) 22, (byte) 50, (byte) 60, (byte) 65, (byte) 108, (byte) 86, (byte) 45,
        (byte) -112, (byte) -59, (byte) 46, (byte) -128, (byte) 90, (byte) 35, (byte) -57, (byte) -27,
        (byte) -122, (byte) 41, (byte) 76,

        (byte) 0, (byte) 0, (byte) 0, (byte) 27,

        (byte) 20, (byte) 119, (byte) -102, (byte) 119, (byte) -87, (byte) 46, (byte) 32, (byte) -88,
        (byte) -32, (byte) 58, (byte) 10, (byte) -72, (byte) -61, (byte) -11, (byte) 115, (byte) -102,
        (byte) -20, (byte) -30, (byte) -22, (byte) -40, (byte) 78, (byte) 117, (byte) 34, (byte) -60,
        (byte) -108, (byte) -38, (byte) -42
    };

    assertArrayEquals(expected, Bytes.joinWithLength(
            new BigInteger("1797693134862315907708391567937874531978602960487560117064444236"),
            new BigInteger("8419718021615851936894783379586492554150218056548598050364644054"))
        );
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