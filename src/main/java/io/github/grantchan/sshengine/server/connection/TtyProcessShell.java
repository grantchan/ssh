package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.connection.TtyMode;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TtyProcessShell extends AbstractLogger {

  private Process process;

  private final InputStream in;
  private final OutputStream err;
  private final OutputStream out;

  private final String[] cmds;

  private TtyInputStream ttyIn;
  private TtyInputStream ttyErr;
  private TtyOutputStream ttyOut;

  private static final ExecutorService threadpool = Executors.newFixedThreadPool(5);

  public TtyProcessShell(InputStream in, OutputStream out, OutputStream err, String... cmds) {
    this.in = in;
    this.out = out;
    this.err = err;
    this.cmds = cmds;
  }

  public void start(Map<TtyMode, Integer> ttyModes) {
    ProcessBuilder pb = new ProcessBuilder();

    pb.command(cmds);

    try {
      process = pb.start();

      ttyIn = new TtyInputStream(process.getInputStream(), ttyModes);
      ttyErr = new TtyInputStream(process.getErrorStream(), ttyModes);
      ttyOut = new TtyOutputStream(process.getOutputStream(), ttyIn, ttyModes);

      threadpool.execute(this::drain);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void drain() {
    try {
      while (true) {
        if (drain(in, ttyOut)) {
          continue;
        }

        if (drain(ttyIn, out)) {
          continue;
        }

        if (drain(ttyErr, err)) {
          continue;
        }

        if ((!process.isAlive()) && (in.available() <= 0) && (ttyIn.available() <= 0) && (ttyErr.available() <= 0)) {
          break;
        }

        Thread.sleep(50);
      }
      shutdown();
    } catch (Exception e) {
      try {
        shutdown();
      } catch (IOException ex) {
        int exitVal = process.exitValue();
        System.out.println("Process exit, with exit value: " + exitVal);
      }
    }
  }

  private boolean drain(InputStream in, OutputStream out) throws IOException {
    int avail = in.available();

    if (avail > 0) {
      byte[] buf = new byte[avail];
      int len = in.read(buf);
      if (len > 0) {
        out.write(buf, 0, len);
        out.flush();

        return true;
      }
    } else if (avail == -1) {
      out.close();
    }

    return false;
  }

  public void shutdown() throws IOException {
    if (process != null) {
      process.destroy();
    }

    for (Closeable c : Arrays.asList(ttyIn, ttyOut, ttyErr)) {
      c.close();
    }
  }
}
