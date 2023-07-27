package com.app.exceptions;

public class UserExistsException extends RuntimeException{
    public UserExistsException(String message){
        super(message);
    }
}
