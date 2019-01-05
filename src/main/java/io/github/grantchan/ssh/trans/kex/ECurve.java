package io.github.grantchan.ssh.trans.kex;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public enum ECurve {

  /**
   * <p>
   * The verifiably random elliptic curve domain parameters over Fp secp256r1 are specified by <br/>
   * the sextuple T = (p,a,b,G,n,h) where the finite field Fp is defined by:
   * </p>
   * <p>&nbsp;&nbsp;&nbsp;
   *   p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF <br/>
   * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
   *     = 2^224 (2^32 − 1) + 2^192 + 2^96 − 1
   * </p>
   * <p>
   * The curve E: y^2 = x^3 + ax + b over Fp is defined by: <br/>
   * &nbsp;&nbsp;&nbsp;
   *   a = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC <br/>
   * &nbsp;&nbsp;&nbsp;
   *   b = 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
   * </p>
   * <p>
   * E was chosen verifiably at random as specified in ANSI X9.62 [X9.62] from the seed: <br/>
   * &nbsp;&nbsp;&nbsp;
   *   S = C49D3608 86E70493 6A6678E1 139D26B7 819F7E90
   * </p>
   * <p>
   * The base point G in compressed form is: <br/>
   * &nbsp;&nbsp;&nbsp;
   *   G = &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
   *         03 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296 <br/>
   * </p>
   * <p>
   * and in uncompressed form is: <br/>
   * &nbsp;&nbsp;&nbsp;
   *   G = &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
   *         04 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296 <br/>
   *   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
   *   4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
   * </p>
   * <p>
   * Finally the order n of G and the cofactor are: <br/>
   * &nbsp;&nbsp;&nbsp;
   *   n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551 <br/>
   * &nbsp;&nbsp;&nbsp;
   *   h = 01
   * </p>
   *
   * @see <a href="http://www.secg.org/sec2-v2.pdf">SEC 2: Recommended Elliptic Curve Domain Parameters</a>
   */
  nistp256() {
    @Override
    public ECParameterSpec ParamSpec() {
      BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
      ECFieldFp Fp = new ECFieldFp(p);

      BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
      BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

      EllipticCurve curve = new EllipticCurve(Fp, a, b);

      ECPoint g = new ECPoint(
          new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
          new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16));

      BigInteger n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
      int h = 1;

      return new ECParameterSpec(curve, g, n, h);
    }
  };

  public abstract ECParameterSpec ParamSpec();
}
