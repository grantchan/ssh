package io.github.grantchan.ssh.arch;

public final class SshConstant {
  public static final int SSH_PACKET_LENGTH        = 4; // a 32-bit of integer
  public static final int SSH_PADDING_LENGTH       = 1; // a 8-bit of byte
  public static final int SSH_PACKET_HEADER_LENGTH = SSH_PACKET_LENGTH + SSH_PADDING_LENGTH;
  public static final int MSG_KEX_COOKIE_SIZE      = 16;
}
