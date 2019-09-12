package io.github.grantchan.sshengine.common;

@FunctionalInterface
public interface IdHolder {
  /**
   * @return the attached id
   */
  int getId();
}
