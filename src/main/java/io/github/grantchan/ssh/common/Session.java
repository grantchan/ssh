package io.github.grantchan.ssh.common;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.util.List;

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
  private List<String> kexParams;

  private Cipher c2sCipher, s2cCipher;
  private int c2sCipherSize = 8, s2cCipherSize = 8;

  private Mac c2sMac, s2cMac;
  private int c2sMacSize = 0, s2cMacSize = 0;

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

  public void setKexParams(List<String> kexParams) {
    this.kexParams = kexParams;
  }

  public List<String> getKexParams() {
    return kexParams;
  }

  public Cipher getC2sCipher() {
    return c2sCipher;
  }

  public void setC2sCipher(Cipher c2sCipher) {
    this.c2sCipher = c2sCipher;
  }

  public Cipher getS2cCipher() {
    return s2cCipher;
  }

  public void setS2cCipher(Cipher s2cCipher) {
    this.s2cCipher = s2cCipher;
  }

  public int getC2sCipherSize() {
    return c2sCipherSize;
  }

  public void setC2sCipherSize(int c2sCipherSize) {
    this.c2sCipherSize = c2sCipherSize;
  }

  public int getS2cCipherSize() {
    return s2cCipherSize;
  }

  public void setS2cCipherSize(int s2cCipherSize) {
    this.s2cCipherSize = s2cCipherSize;
  }

  public Mac getC2sMac() {
    return c2sMac;
  }

  public void setC2sMac(Mac c2sMac) {
    this.c2sMac = c2sMac;
  }

  public Mac getS2cMac() {
    return s2cMac;
  }

  public void setS2cMac(Mac s2cMac) {
    this.s2cMac = s2cMac;
  }

  public int getC2sMacSize() {
    return c2sMacSize;
  }

  public void setC2sMacSize(int c2sMacSize) {
    this.c2sMacSize = c2sMacSize;
  }

  public int getS2cMacSize() {
    return s2cMacSize;
  }

  public void setS2cMacSize(int s2cMacSize) {
    this.s2cMacSize = s2cMacSize;
  }
}
