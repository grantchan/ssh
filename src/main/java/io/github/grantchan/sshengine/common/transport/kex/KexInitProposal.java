package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.common.NamedObject;
import io.github.grantchan.sshengine.common.transport.cipher.CipherFactories;
import io.github.grantchan.sshengine.common.transport.compression.CompressionFactories;
import io.github.grantchan.sshengine.common.transport.mac.MacFactories;
import io.github.grantchan.sshengine.common.transport.signature.SignatureFactories;

import java.util.EnumSet;
import java.util.Set;
import java.util.function.Supplier;

public enum KexInitProposal implements NamedObject {

  KEX             (Param.KEX,             "KEX",              KexHandlerFactories::getNames),
  SERVER_HOST_KEY (Param.SERVER_HOST_KEY, "Server Host Key",  SignatureFactories::getNames),
  ENCRYPTION_C2S  (Param.ENCRYPTION_C2S,  "Encryption C2S",   CipherFactories::getNames),
  ENCRYPTION_S2C  (Param.ENCRYPTION_S2C,  "Encryption S2C",   CipherFactories::getNames),
  MAC_C2S         (Param.MAC_C2S,         "MAC C2S",          MacFactories::getNames),
  MAC_S2C         (Param.MAC_S2C,         "MAC S2C",          MacFactories::getNames),
  COMPRESSION_C2S (Param.COMPRESSION_C2S, "Compression C2S",  CompressionFactories::getNames),
  COMPRESSION_S2C (Param.COMPRESSION_S2C, "Compression S2C",  CompressionFactories::getNames),
  LANGUAGE_C2S    (Param.LANGUAGE_C2S,    "Language C2S",     () -> ""),
  LANGUAGE_S2C    (Param.LANGUAGE_S2C,    "Language S2C",     () -> "");

  public final static Set<KexInitProposal> ALL = EnumSet.allOf(KexInitProposal.class);

  private int id;
  private String name;
  private Supplier<String> proposals;

  KexInitProposal(int id, String name, Supplier<String> proposals) {
    this.id = id;
    this.name = name;
    this.proposals = proposals;
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

  public class Param {

    public static final int KEX             = 0;
    public static final int SERVER_HOST_KEY = 1;
    public static final int ENCRYPTION_C2S  = 2;
    public static final int ENCRYPTION_S2C  = 3;
    public static final int MAC_C2S         = 4;
    public static final int MAC_S2C         = 5;
    public static final int COMPRESSION_C2S = 6;
    public static final int COMPRESSION_S2C = 7;
    public static final int LANGUAGE_C2S    = 8;
    public static final int LANGUAGE_S2C    = 9;
  }
}
