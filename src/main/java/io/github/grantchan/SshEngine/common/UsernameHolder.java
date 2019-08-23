package io.github.grantchan.SshEngine.common;

@FunctionalInterface
public interface UsernameHolder {
  /**
   * @return the attached username
   */
  String getUsername();
}
