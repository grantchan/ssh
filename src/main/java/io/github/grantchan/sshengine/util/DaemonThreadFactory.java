package io.github.grantchan.sshengine.util;

import io.github.grantchan.sshengine.common.AbstractLogger;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class DaemonThreadFactory extends AbstractLogger implements ThreadFactory {
  private final ThreadGroup group;
  private final AtomicInteger threadNum = new AtomicInteger(1);

  public DaemonThreadFactory() {
    SecurityManager sm = java.lang.System.getSecurityManager();

    this.group = (sm != null) ? sm.getThreadGroup() : Thread.currentThread().getThreadGroup();
  }

  @Override
  public Thread newThread(Runnable runnable) {
    Thread t = new Thread(group, runnable, "daemon-thread-" + threadNum.getAndIncrement(), 0);
    t.setDaemon(true);

    logger.trace("Thread created, group:{}, name:{}, runnable:{}", group, t.getName(), runnable);

    return t;
  }
}
