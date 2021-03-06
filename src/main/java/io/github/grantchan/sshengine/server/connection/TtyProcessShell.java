package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.connection.TtyMode;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;

public class TtyProcessShell extends AbstractLogger {

  private Process process;

  private final InputStream in;
  private final OutputStream err;
  private final OutputStream out;

  private final String[] cmds;

  private TtyInputStream ttyIn;
  private TtyInputStream ttyErr;
  private TtyOutputStream ttyOut;

  private ExitCallback callback;

  private final Thread drainer = new Thread(this::drain);

  public TtyProcessShell(InputStream in, OutputStream out, OutputStream err, String... cmds) {
    this.in = in;
    this.out = out;
    this.err = err;
    this.cmds = cmds;
  }

  public void start(Map<TtyMode, Integer> ttyModes) throws IOException {
    ProcessBuilder pb = new ProcessBuilder();

    pb.command(cmds);

    process = pb.start();

    ttyIn = new TtyInputStream(process.getInputStream(), ttyModes);
    ttyErr = new TtyInputStream(process.getErrorStream(), ttyModes);
    ttyOut = new TtyOutputStream(process.getOutputStream(), ttyIn, ttyModes);

    drainer.setDaemon(true);
    drainer.start();
  }

  public String[] getCmds() {
    return this.cmds;
  }

  public boolean isAlive() {
    return process != null && process.isAlive();
  }

  private void drain() {
    try {
      while (true) {
        if ((in != null) && drain(in, ttyOut)) {
          continue;
        }

        if ((out != null) && drain(ttyIn, out)) {
          continue;
        }

        if ((err != null) && drain(ttyErr, err)) {
          continue;
        }

        if ((!process.isAlive()) && (in != null && in.available() <= 0) &&
            (ttyIn.available() <= 0) && (ttyErr.available() <= 0)) {
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

  public void setExitCallback(ExitCallback callback) {
    this.callback = callback;
  }

  public void shutdown() throws IOException {
    if (process != null) {
      process.destroy();
    }

    for (Closeable c : Arrays.asList(ttyIn, ttyOut, ttyErr)) {
      c.close();
    }

    // notify the session channel, owner of this process, that the process is going to shutdown,
    // so that it can do some cleanup
    if (process != null && callback != null) {
      callback.onExit(process.exitValue());
    }
  }
}
