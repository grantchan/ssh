package io.github.grantchan.ssh.common.transport.kex;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.common.transport.compression.CompressionFactories;
import io.github.grantchan.ssh.common.transport.mac.MacFactories;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;

import java.util.EnumSet;
import java.util.Set;
import java.util.function.Supplier;

public enum KexInitProposal implements NamedObject {

  KEX             (0, "KEX",              KexHandlerFactories::getNames),
  SERVER_HOST_KEY (1, "Server Host Key",  SignatureFactories::getNames),
  ENCRYPTION_C2S  (2, "Encryption C2S",   CipherFactories::getNames),
  ENCRYPTION_S2C  (3, "Encryption S2C",   CipherFactories::getNames),
  MAC_C2S         (4, "MAC C2S",          MacFactories::getNames),
  MAC_S2C         (5, "MAC S2C",          MacFactories::getNames),
  COMPRESSION_C2S (6, "Compression C2S",  CompressionFactories::getNames),
  COMPRESSION_S2C (7, "Compression S2C",  CompressionFactories::getNames),
  LANGUAGE_C2S    (8, "Language C2S",     () -> ""),
  LANGUAGE_S2C    (9, "Language S2C",     () -> "");

  private final static Set<KexInitProposal> ALL = EnumSet.allOf(KexInitProposal.class);

  private int id;
  private String name;
  private Supplier<String> proposals;

  KexInitProposal(int id, String name, Supplier<String> proposals) {
    this.id = id;
    this.name = name;
    this.proposals = proposals;
  }

  public static KexInitProposal from(int id) {
    for (KexInitProposal kip : ALL) {
      if (kip.id == id) {
        return kip;
      }
    }
    return null;
  }

  public int getId() {
    return id;
  }

  @Override
  public String getName() {
    return name;
  }

  public Supplier<String> getProposals() {
    return proposals;
  }
}
