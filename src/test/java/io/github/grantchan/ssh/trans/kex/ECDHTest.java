package io.github.grantchan.ssh.trans.kex;

import org.junit.Test;

import java.math.BigInteger;
import java.security.spec.ECPoint;

import static org.junit.Assert.assertArrayEquals;

public class ECDHTest {

  @Test
  public void testFromECPoint_whenXandYCoorNeedToStripZeroesInFront() {
    ECPoint pt = new ECPoint(
        new BigInteger("66723664390528148552140073353014262683092939813711052811690869256697864646305", 10),
        new BigInteger("95561928245012935811838193944396323609532976687304528394304360388584956688121", 10)
    );

    assertArrayEquals(
        ECDH.toBytes(pt, ECurve.nistp256.ParamSpec().getCurve()),
        new byte[] {
            (byte) 0x04,
            (byte) 0x93, (byte) 0x84, (byte) 0x41, (byte) 0x77, (byte) 0x89, (byte) 0x99, (byte) 0xC9, (byte) 0x47,
            (byte) 0xA5, (byte) 0x4C, (byte) 0x86, (byte) 0xA,  (byte) 0x60, (byte) 0xFC, (byte) 0x23, (byte) 0xE3,
            (byte) 0x32, (byte) 0x55, (byte) 0x47, (byte) 0xB,  (byte) 0xB,  (byte) 0x53, (byte) 0x85, (byte) 0x2A,
            (byte) 0xC,  (byte) 0x84, (byte) 0x7B, (byte) 0xB6, (byte) 0x33, (byte) 0x41, (byte) 0xEE, (byte) 0xA1,
            (byte) 0xD3, (byte) 0x46, (byte) 0x22, (byte) 0x78, (byte) 0x2D, (byte) 0xF5, (byte) 0x6,  (byte) 0x10,
            (byte) 0x8D, (byte) 0x6A, (byte) 0xAA, (byte) 0xB0, (byte) 0xA2, (byte) 0xD6, (byte) 0x9,  (byte) 0xF1,
            (byte) 0xD4, (byte) 0xF8, (byte) 0x71, (byte) 0xE8, (byte) 0x8B, (byte) 0xCA, (byte) 0xA5, (byte) 0x49,
            (byte) 0xBD, (byte) 0x1E, (byte) 0xC3, (byte) 0x52, (byte) 0xEC, (byte) 0x72, (byte) 0xF6, (byte) 0xF9}
    );
  }
}