package io.github.grantchan.ssh.common.transport.compression;

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

    try {
      deflater.setInput(data);
      deflater.finish();

      byte[] zipped = new byte[BUFFER_SIZE];
      while (!deflater.finished()) {
        int cnt = deflater.deflate(zipped);
        out.write(zipped, 0, cnt);
      }
      return out.toByteArray();
    } finally {
      deflater.end();
    }
  }

  @Override
  public byte[] decompress(byte[] data) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);

    try {
      inflater.setInput(data);

      byte[] unzipped = new byte[BUFFER_SIZE];
      while (!inflater.finished()) {
        int cnt = inflater.inflate(unzipped);
        out.write(unzipped, 0, cnt);
      }
      return out.toByteArray();
    } catch (DataFormatException e) {
      throw new IOException("Error decompressing data");
    } finally {
      inflater.end();
    }
  }
}
