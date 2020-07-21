package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.connection.TtyMode;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

public class TtyOutputStream extends FilterOutputStream {

  private static final Set<TtyMode> MODE_OPTIONS =
      Collections.unmodifiableSet(EnumSet.of(TtyMode.ECHO, TtyMode.INLCR, TtyMode.ICRNL, TtyMode.IGNCR));

  private final TtyInputStream echo;

  private final Set<TtyMode> modes;
  private final Integer CR, LF;

  public TtyOutputStream(OutputStream out, TtyInputStream echo, Map<TtyMode, Integer> modes) {
    this(out, echo, TtyMode.filterOptions(modes, MODE_OPTIONS));
  }

  public TtyOutputStream(OutputStream out, TtyInputStream echo, Set<TtyMode> modes) {
    super(out);

    this.echo = modes.contains(TtyMode.ECHO) ?
        Objects.requireNonNull(echo, "Invalid parameter - echo is null") : null;

    this.modes = modes;

    if (modes.contains(TtyMode.ICRNL)) {
      CR = (int) '\n';
    } else if (modes.contains(TtyMode.IGNCR)) {
      CR = null;
    } else {
      CR = (int) '\r';
    }

    LF = modes.contains(TtyMode.INLCR) ? (int) '\r' : (int) '\n';
  }

  @Override
  public void write(int b) throws IOException {
    Integer c;

    if (b == '\r' && CR != null) {
      c = CR;
    } else if (b == '\n') {
      c = LF;
    } else {
      c = b;
    }

    if (c != null) {
      out.write(c);
      if (modes.contains(TtyMode.ECHO)) {
        echo.write(c);
      }
    }
  }

  @Override
  public void write(byte[] buf, int off, int len) throws IOException {
    int pos = 0;
    for (int i = off; i < off + len; i++) {
      int c = buf[i] & 0xFF;
      if (c == '\r' || c == '\n') {
        out.write(buf, pos, i - pos);
        if (modes.contains(TtyMode.ECHO)) {
          echo.write(buf, pos, i - pos);
        }

        pos = i + 1;
        write(c);
      }
    }
    out.write(buf, pos, off + len - pos);
  }
}
