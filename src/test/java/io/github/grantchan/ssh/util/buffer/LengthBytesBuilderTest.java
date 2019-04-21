package io.github.grantchan.ssh.util.buffer;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;

public class LengthBytesBuilderTest {

  @Test
  public void testConcatByteArraysToLengthByteArray() {
    byte[] a = {(byte) 0x1A, (byte) 0xEB, (byte) 0xFA, (byte) 0x66};
    byte[] b = {(byte) 0x29, (byte) 0x8F};

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04,
        (byte) 0x1A, (byte) 0xEB, (byte) 0xFA, (byte) 0x66,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02,
        (byte) 0x29, (byte) 0x8F
    };

    assertArrayEquals(LengthBytesBuilder.concat(a, b), expected);
    assertArrayEquals(LengthBytesBuilder.concat(a, null, b), expected);
    assertArrayEquals(LengthBytesBuilder.concat(null, a, b), expected);
    assertArrayEquals(LengthBytesBuilder.concat(a, b, null), expected);
  }

  @Test
  public void testConcatStringByteArraysToLengthByteArray() {
    byte[] a = "12345678".getBytes(StandardCharsets.UTF_8);
    byte[] b = " abcdefghijklmnopq".getBytes(StandardCharsets.UTF_8);

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08,
        (byte) '1', (byte) '2', (byte) '3', (byte) '4',
        (byte) '5', (byte) '6', (byte) '7', (byte) '8',
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x12,
        (byte) ' ', (byte) 'a', (byte) 'b', (byte) 'c',
        (byte) 'd', (byte) 'e', (byte) 'f', (byte) 'g',
        (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k',
        (byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o',
        (byte) 'p', (byte) 'q'
    };

    assertArrayEquals(LengthBytesBuilder.concat(a, b), expected);
  }

  @Test
  public void testConcatBooleansToLengthByteArray() {
    byte[] expected = {
        (byte) 0x01, (byte) 0x00, (byte) 0x00
    };

    assertArrayEquals(LengthBytesBuilder.concat(true, false, false), expected);
  }

  @Test
  public void testConcatIntegersToLengthByteArray() {
    int a = 0x305, b = 0x9, c = 0xF2, d = 0xAE6;

    byte[] expected = {
        (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x05,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xF2,
        (byte) 0x00, (byte) 0x00, (byte) 0x0A, (byte) 0xE6
    };

    assertArrayEquals(LengthBytesBuilder.concat(a, b, c, d), expected);
  }

  @Test
  public void testConcatStringsToLengthByteArray() {
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

    assertArrayEquals(LengthBytesBuilder.concat(a, b), expected);
    assertArrayEquals(LengthBytesBuilder.concat(a, null, b), expected);
    assertArrayEquals(LengthBytesBuilder.concat(null, a, b), expected);
    assertArrayEquals(LengthBytesBuilder.concat(a, b, null, null), expected);
  }
}