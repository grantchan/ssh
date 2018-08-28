package io.github.grantchan.ssh.handler;

public class SshConstant {
  static final int  SSH_PACKET_LENGTH         = 4; // a 32-bit of integer
  static final int  SSH_PADDING_LENGTH        = 1; // a 8-bit of byte
  static final int  SSH_PACKET_HEADER_LENGTH  = SSH_PACKET_LENGTH + SSH_PADDING_LENGTH;
  static final int  MSG_KEX_COOKIE_SIZE       = 16;

  static final byte SSH_MSG_KEXINIT           = 20;
}
