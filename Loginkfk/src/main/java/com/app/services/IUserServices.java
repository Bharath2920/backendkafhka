package com.app.services;

import com.app.entities.UserModel;

import java.util.List;
import java.util.Map;

public interface IUserServices {
    public boolean addUser(UserModel obj) throws RuntimeException;
    public List<UserModel> getAllUsers();
    public boolean updateUserRole(String email, String newRole);
}
