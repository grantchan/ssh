package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.connection.TtyMode;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

public class TtyInputStream extends FilterInputStream {

  private static final Set<TtyMode> MODE_OPTIONS =
      Collections.unmodifiableSet(EnumSet.of(TtyMode.ONLCR, TtyMode.OCRNL, TtyMode.ONLRET, TtyMode.ONOCR));

  private final Set<TtyMode> modes;
  private int lastCh;
  private final Integer CR;

  private final Deque<Byte> fifo = new LinkedList<>();

  public TtyInputStream(InputStream in, Map<TtyMode, Integer> modes) {
    this(in, TtyMode.filterOptions(modes, MODE_OPTIONS));
  }

  protected TtyInputStream(InputStream in, Set<TtyMode> modes) {
    super(in);

    this.modes = modes;
    this.CR = modes.contains(TtyMode.OCRNL) ? (int) '\n' : (int) '\r';
  }

  public void write(int b) {
    fifo.add((byte) b);
  }

  public void write(byte[] buf, int off, int len) {
    for (int i = off; i < off + len; i++) {
      fifo.add(buf[i]);
    }
  }

  @Override
  public int available() throws IOException {
    return fifo.size() + super.available();
  }

  @Override
  public int read() throws IOException {
    int c;

    if (fifo.size() > 0) {
      c = fifo.poll();
    } else {
      c = in.read();
    }

    if (c == '\r') {
      c = CR;
    } else if (c == '\n') {
      if ((modes.contains(TtyMode.ONLCR) || modes.contains(TtyMode.ONOCR)) && lastCh != '\r') {
        fifo.addFirst((byte) '\n');
        c = '\r';
      } else if (modes.contains(TtyMode.ONLRET)) {
        c = '\r';
      }
    }

    lastCh = c; // Cached it for LF handling

    return c;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int nb = 0;
    for (int i = off; (i < off + len) && (available() > 0); i++, nb++) {
      b[i] = (byte) read();
    }

    return nb;
  }
}
