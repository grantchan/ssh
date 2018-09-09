package io.github.grantchan.ssh.kex;

public class Session {

  /*
   * RFC 4253:
   * Both the 'protoversion' and 'softwareversion' strings MUST consist of
   * printable US-ASCII characters, with the exception of whitespace
   * characters and the minus sign (-).
   */
  private       String clientVer = null;            // client identification
  private final String serverVer = "SSH-2.0-DEMO";  // server identification

  private byte[] clientKexInit = null; // the payload of the client's SSH_MSG_KEXINIT
  private byte[] serverKexInit = null; // the payload of the server's SSH_MSG_KEXINIT

  public String getClientVer() {
    return clientVer;
  }

  public void setClientVer(String clientVer) {
    this.clientVer = clientVer;
  }

  public String getServerVer() {
    return serverVer;
  }

  public byte[] getClientKexInit() {
    return clientKexInit;
  }

  public void setClientKexInit(byte[] clientKexInit) {
    this.clientKexInit = clientKexInit;
  }

  public byte[] getServerKexInit() {
    return serverKexInit;
  }

  public void setServerKexInit(byte[] serverKexInit) {
    this.serverKexInit = serverKexInit;
  }

}
