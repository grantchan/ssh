package io.github.grantchan.sshengine.common;

@FunctionalInterface
public interface UsernameHolder {
  /**
   * @return the attached username
   */
  String getUsername();
}
