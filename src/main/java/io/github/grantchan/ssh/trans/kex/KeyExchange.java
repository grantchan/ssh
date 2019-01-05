package io.github.grantchan.ssh.trans.kex;

import java.math.BigInteger;

public abstract class KeyExchange {

  BigInteger pubKey; // exchange value sent by the client
  byte[]     receivedPubKey; // exchange value sent by the server

  byte[] getPubKey() {
    return this.pubKey.toByteArray();
  }

  byte[] getReceivedPubKey() {
    return this.receivedPubKey;
  }

  void receivedPubKey(byte[] key) {
    this.receivedPubKey = key;
  }

  abstract byte[] getSecretKey();

}
