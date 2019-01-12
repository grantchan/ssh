package io.github.grantchan.ssh.common.transport.kex;

public class KexInitParam {
  
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
