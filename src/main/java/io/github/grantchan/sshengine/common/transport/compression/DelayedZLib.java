package io.github.grantchan.sshengine.common.transport.compression;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class DelayedZLib implements Compression {

  private static final int BUFFER_SIZE = 1024;

  private Deflater deflater = new Deflater();
  private Inflater inflater = new Inflater();

  @Override
  public byte[] compress(byte[] data) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);

    deflater.setInput(data);
    deflater.finish();

    byte[] buf = new byte[BUFFER_SIZE];
    for (int len = deflater.deflate(buf); len > 0; len = deflater.deflate(buf)) {
      out.write(buf, 0, len);
    }
    return out.toByteArray();
  }

  @Override
  public byte[] decompress(byte[] data) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);

    try {
      inflater.setInput(data);

      byte[] buf = new byte[BUFFER_SIZE];
      for (int len = inflater.inflate(buf); len > 0; len = inflater.inflate(buf)) {
        out.write(buf, 0, len);
      }
      return out.toByteArray();
    } catch (DataFormatException e) {
      throw new IOException("Error decompressing data");
    }
  }
}
