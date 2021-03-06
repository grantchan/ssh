package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.transport.kex.ClientDhGroup;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.NamedObject;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.digest.DigestFactories;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.server.transport.kex.ServerDhGroup;

import java.security.MessageDigest;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum KexGroupFactories implements NamedObject, KexGroupFactory {

  /*
   * This ECDH method may be implemented because it is smaller and faster than using large FFC
   * primes with traditional Diffie-Hellman (DH).
   *
   * It is not listed in [CNSA-SUITE], so it is not currently appropriate for TOP SECRET.
   *
   * This method MAY be implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.14">
   *   ecdh-sha2-nistp521</a>
   */
  ecdh521("ecdh-sha2-nistp521") {
    @Override
    public KexGroup create(AbstractSession session) throws SshException {
      return getKexHandler(DigestFactories.sha512.create(), new ECDH(ECurve.nistp521), session);
    }
  },

  /*
   * This ECDH method should be implemented because it is smaller and faster than using large FFC
   * primes with traditional Diffie-Hellman (DH).
   *
   * Given [CNSA-SUITE], it is considered good enough for TOP SECRET.
   *
   * If traditional ECDH key exchange methods are implemented, then this method SHOULD be
   * implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.13">
   *   ecdh-sha2-nistp384</a>
   */
//  ecdh384("ecdh-sha2-nistp384") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha384.create(), new ECDH(ECurve.nistp384), session);
//    }
//  },

  /*
   * Elliptic Curve Diffie-Hellman (ECDH) are often implemented because they are smaller and faster
   * than using large FFC primes with traditional Diffie-Hellman (DH).
   *
   * However, given [CNSA-SUITE] and [safe-curves], this curve may not be as useful and strong as
   * desired for handling TOP SECRET information for some applications. The SSH development
   * community is divided on this and many implementations do exist. If traditional ECDH key
   * exchange methods are implemented, then this method SHOULD be implemented.
   *
   * It is advisable to match the ECDSA and ECDH algorithms to use the same family of curves.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.12">
   *   ecdh-sha2-nistp256</a>
   */
//  ecdh256("ecdh-sha2-nistp256") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha256.create(), new ECDH(ECurve.nistp256), session);
//    }
//  },

  /*
   * The use of this 8192-bit MODP group is going to be slower than what may be desirable.
   *
   * It is provided to help those who wish to avoid using ECC algorithms.
   *
   * This method MAY be implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.11">
   *   diffie-hellman-group18-sha512</a>
   */
//  dhg18sha512("diffie-hellman-group18-sha512") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha512.create(), new DH(DhGroup.P18), session);
//    }
//  },

  /*
   * The use of this 6144-bit MODP group is going to be slower than what may be desirable.
   *
   * It is provided to help those who wish to avoid using ECC algorithms.
   *
   * This method MAY be implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.10">
   *   diffie-hellman-group17-sha512</a>
   */
//  dhg17sha512("diffie-hellman-group17-sha512") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha512.create(), new DH(DhGroup.P17), session);
//    }
//  },

  /*
   * The use of FFC DH is well understood and trusted.
   *
   * Adding larger modulus sizes and protecting with SHA2-512 should give enough head room to be
   * ready for the next scare that someone has pre-computed it. This modulus (4096-bit) is larger
   * than that required by [CNSA-SUITE] and should be sufficient to inter-operate with more paranoid
   * nation-states.
   *
   * This method SHOULD be implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.9">
   *   diffie-hellman-group16-sha512</a>
   */
//  dhg16sha512("diffie-hellman-group16-sha512") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha512.create(), new DH(DhGroup.P16), session);
//    }
//  },

  /*
   * The use of this 3072-bit MODP group would be equally justified to use SHA2-384 as the hash
   * rather than SHA2-512.
   *
   * However, some small implementations would rather only worry about two rather than three new
   * hashing functions. This group does not really provide much additional head room over the
   * 2048-bit group14 FFC DH and the predominate open source implementations are not adopting it.
   *
   * This method MAY be implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.8">
   *   diffie-hellman-group15-sha512</a>
   */
//  dhg15sha512("diffie-hellman-group15-sha512") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha512.create(), new DH(DhGroup.P15), session);
//    }
//  },

  /*
   * This key exchange uses the group14 (a 2048-bit MODP group) along with a SHA-2 (SHA2-256) hash.
   *
   * This represents the smallest Finite Field Cryptography (FFC) Diffie-Hellman (DH) key
   * exchange method considered to be secure. It is a reasonably simple transition to move from
   * SHA-1 to SHA-2.
   *
   * This method MUST be implemented.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.7">
   *   diffie-hellman-group14-sha256</a>
   */
  dhg14sha256("diffie-hellman-group14-sha256") {
    @Override
    public KexGroup create(AbstractSession session) throws SshException {
      return getKexHandler(DigestFactories.sha256.create(), new DH(DhGroup.P14), session);
    }
  },

  /*
   * This method uses [RFC3526] group14 (a 2048-bit MODP group) which is still a reasonable size.
   *
   * This key exchange group uses SHA-1 which has security concerns [RFC6194]. However, this group
   * is still strong enough and is widely deployed. This method is being moved from MUST to SHOULD
   * to aid in transition to stronger SHA-2 based hashes.
   *
   * This method will transition to SHOULD NOT when SHA-2 alternatives are more generally available.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.6">
   *   diffie-hellman-group14-sha1</a>
   */
//  dhg14sha1("diffie-hellman-group14-sha1") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha1.create(), new DH(DhGroup.P14), session);
//    }
//  },

  /*
   * This method uses [RFC7296] Oakley Group 2 (a 1024-bit MODP group) and SHA-1 [RFC3174].
   *
   * Due to recent security concerns with SHA-1 [RFC6194] and with MODP groups with less than
   * 2048 bits (see [LOGJAM] and [NIST-SP-800-131Ar1]), this method is considered insecure.
   * This method is being moved from MUST to SHOULD NOT instead of MUST NOT only to allow a
   * transition time to get off of it.
   *
   * There are many old implementations out there that may still need to use this key exchange, it
   * should be removed from server implementations as quickly as possible.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.5">
   *   diffie-hellman-group1-sha1</a>
   */
//  dhg1sha1("diffie-hellman-group1-sha1") {
//    @Override
//    public KexGroup create(AbstractSession session) throws SshException {
//      return getKexGroup(DigestFactories.sha1.create(), new DH(DhGroup.P1), session);
//    }
//  },

  /*
   * This set of ephemerally generated key exchange groups uses SHA2-256 as defined in [RFC4419].
   *
   * [I-D.ietf-curdle-sshenginessh-dh-group-exchange] mandates implementations avoid any MODP group with
   * less than 2048 bits.
   *
   * This key exchange MAY be used.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.4">
   *   diffie-hellman-group-exchange-sha256</a>
   */
//  dhgexsha256("diffie-hellman-group-exchange-sha256") {
//    @Override
//    public KexGroup create(AbstractSession s) throws SshException {
//      return new ServerDhGroupEx(DigestFactories.sha256.create(), s);
//    }
//  },

  /*
   * This set of ephemerally generated key exchange groups uses SHA-1 as defined in [RFC4419].
   *
   * However, SHA-1 has security concerns provided in [RFC6194]. It is recommended that these key
   * exchange groups NOT be used.
   *
   * This key exchange SHOULD NOT be used.
   *
   * @see
   * <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.3">
   *   diffie-hellman-group-exchange-sha1</a>
   */
//  dhgexsha1("diffie-hellman-group-exchange-sha1") {
//    @Override
//    public KexGroup create(AbstractSession s) throws SshException {
//      return new ServerDhGroupEx(DigestFactories.sha1.create(), s);
//    }
//  }
;

  private static KexGroup getKexHandler(MessageDigest md, Kex ke, AbstractSession session) {
    return session instanceof ServerSession ?
        new ServerDhGroup(md, ke, (ServerSession)session) :
        new ClientDhGroup(md, ke, (ClientSession)session);
  }

  public static final Set<KexGroupFactories> values =
      Collections.unmodifiableSet(EnumSet.allOf(KexGroupFactories.class));

  public String name;

  KexGroupFactories(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static KexGroup create(String name, AbstractSession s) throws SshException {
    KexGroupFactories f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(s);
  }
}
