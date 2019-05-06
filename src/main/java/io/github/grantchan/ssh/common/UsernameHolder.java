package io.github.grantchan.ssh.common;

@FunctionalInterface
public interface UsernameHolder {
  /**
   * @return the attached username
   */
  String getUsername();
}
