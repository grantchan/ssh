package io.github.grantchan.ssh.trans.kex;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public enum ECurve {

  /**
   * The verifiably random elliptic curve domain parameters over Fp secp256r1 are specified by
   * the sextuple T = (p,a,b,G,n,h) where the finite field Fp is defined by:
   *   p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
   *     = 2^224 (2^32 − 1) + 2^192 + 2^96 − 1
   * The curve E: y^2 = x^3 + ax + b over Fp is defined by:
   *   a = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC
   *   b = 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
   * E was chosen verifiably at random as specified in ANSI X9.62 [X9.62] from the seed:
   *   S = C49D3608 86E70493 6A6678E1 139D26B7 819F7E90
   * The base point G in compressed form is:
   *   G =       03 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
   * and in uncompressed form is:
   *   G =       04 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
   *   4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
   * Finally the order n of G and the cofactor are:
   *   n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
   *   h = 01
   *
   * @see <a href="http://www.secg.org/sec2-v2.pdf">SEC 2: Recommended Elliptic Curve Domain Parameters</a>
   */
  nistp256() {
    @Override
    public ECParameterSpec value() {
      // odd prime
      BigInteger p =
          new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);

      ECFieldFp Fp = new ECFieldFp(p);

      // parameter a, b belong to Fp, satisfy 4a^3 + 27b^2 = 0(mod p)
      BigInteger a =
          new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
      BigInteger b =
          new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

      EllipticCurve curve = new EllipticCurve(Fp, a, b);

      // generator
      ECPoint g = new ECPoint(
          new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
          new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16));

      BigInteger n =
          new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
      int h = 1;

      return new ECParameterSpec(curve, g, n, h);
    }
  },

  /**
   * The verifiably random elliptic curve domain parameters over Fp secp384r1 are specified by
   * the sextuple T = (p,a,b,G,n,h) where the finite field Fp is defined by:
   *   p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF
   *       00000000 00000000 FFFFFFFF
   *     = 2^384 - 2^128 − 2^96 + 2^32 − 1
   * The curve E: y^2 = x^3 + ax + b over Fp is defined by:
   *   a = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF
   *       00000000 00000000 FFFFFFFC
   *   b = B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D
   *       8A2ED19D 2A85C8ED D3EC2AEF
   * E was chosen verifiably at random as specified in ANSI X9.62 [X9.62] from the seed:
   *   S = A335926A A319A27A 1D00896A 6773A482 7ACDAC73
   * The base point G in compressed form is:
   *   G =       03 AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38
   *       5502F25D BF55296C 3A545E38 72760AB7
   * and in uncompressed form is:
   *   G =       04 AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38
   *       5502F25D BF55296C 3A545E38 72760AB7 3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD
   *       289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F
   * Finally the order n of G and the cofactor are:
   *   n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF 581A0DB2
   *       48B0A77A ECEC196A CCC52973
   *   h = 01
   *
   * @see <a href="http://www.secg.org/sec2-v2.pdf">SEC 2: Recommended Elliptic Curve Domain Parameters</a>
   */
  nistp384() {
    @Override
    public ECParameterSpec value() {
      // odd prime
      BigInteger p =
          new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" +
                         "FFFFFFFF0000000000000000FFFFFFFF", 16);

      ECFieldFp Fp = new ECFieldFp(p);

      // parameter a, b belong to Fp, satisfy 4a^3 + 27b^2 = 0(mod p)
      BigInteger a =
          new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" +
                         "FFFFFFFF0000000000000000FFFFFFFC", 16);
      BigInteger b =
          new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A" +
                         "C656398D8A2ED19D2A85C8EDD3EC2AEF", 16);

      EllipticCurve curve = new EllipticCurve(Fp, a, b);

      // generator
      ECPoint g = new ECPoint(
          new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38" +
                         "5502F25DBF55296C3A545E3872760AB7", 16),
          new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0" +
                         "0A60B1CE1D7E819D7A431D7C90EA0E5F", 16));

      BigInteger n =
          new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF" +
                         "581A0DB248B0A77AECEC196ACCC52973", 16);
      int h = 1;

      return new ECParameterSpec(curve, g, n, h);
    }
  },

  /**
   * The verifiably random elliptic curve domain parameters over Fp secp521r1 are specified by
   * the sextuple T = (p,a,b,G,n,h) where the finite field Fp is defined by:
   *   p =     01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
   *       FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
   *     = 2^521 − 1
   * The curve E: y^2 = x^3 + ax + b over Fp is defined by:
   *   a =     01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
   *       FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC
   *   b =     0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991 8EF109E1
   *       56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4 6B503F00
   * E was chosen verifiably at random as specified in ANSI X9.62 [X9.62] from the seed:
   *   S = D09E8800 291CB853 96CC6717 393284AA A0DA64BA
   * The base point G in compressed form is:
   *   G =   0200C6 858E06B7 0404E9CD 9E3ECB66 2395B442 9C648139 053FB521 F828AF60 6B4D3DBA
   *       A14B5E77 EFE75928 FE1DC127 A2FFA8DE 3348B3C1 856A429B F97E7E31 C2E5BD66
   * and in uncompressed form is:
   *   G =       04 00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F B521F828 AF606B4D
   *       3DBAA14B 5E77EFE7 5928FE1D C127A2FF A8DE3348 B3C1856A 429BF97E 7E31C2E5 BD660118
   *       39296A78 9A3BC004 5C8A5FB4 2C7D1BD9 98F54449 579B4468 17AFBD17 273E662C 97EE7299
   *       5EF42640 C550B901 3FAD0761 353C7086 A272C240 88BE9476 9FD16650
   * Finally the order n of G and the cofactor are:
   *   n =     01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFA
   *       51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8 899C47AE BB6FB71E 91386409
   *   h = 01
   *
   * @see <a href="http://www.secg.org/sec2-v2.pdf">SEC 2: Recommended Elliptic Curve Domain Parameters</a>
   */
  nistp521() {
    @Override
    public ECParameterSpec value() {
      // odd prime
      BigInteger p =
          new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

      ECFieldFp Fp = new ECFieldFp(p);

      // parameter a, b belong to Fp, satisfy 4a^3 + 27b^2 = 0(mod p)
      BigInteger a =
          new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16);
      BigInteger b =
          new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1" +
                         "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16);

      EllipticCurve curve = new EllipticCurve(Fp, a, b);

      // generator
      ECPoint g = new ECPoint(
          new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D" +
                         "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
          new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E" +
                         "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16));

      BigInteger n =
          new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                         "FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16);
      int h = 1;

      return new ECParameterSpec(curve, g, n, h);
    }
  };

  public abstract ECParameterSpec value();
}
