package io.github.grantchan.SshEngine.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractLogger {

  protected final Logger logger;

  protected AbstractLogger() {
    String name = getClass().getName();
    this.logger = LoggerFactory.getLogger(name);
  }
}
