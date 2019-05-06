package io.github.grantchan.ssh.common;

@FunctionalInterface
public interface IdHolder {
  /**
   * @return the attached id
   */
  byte[] getId();
}
