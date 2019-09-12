package io.github.grantchan.sshengine.common.transport.compression;

import java.io.IOException;

public interface Compression {

  byte[] compress(byte[] data);

  byte[] decompress(byte[] data) throws IOException;
}
