package org.graylog2.security;

public class UnauthorizedClassLoadingException extends Exception{
    public UnauthorizedClassLoadingException(String message) {
        super(message);
    }
}
