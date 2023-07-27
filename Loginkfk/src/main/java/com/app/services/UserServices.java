package com.app.services;

import com.app.entities.UserModel;
import com.app.exceptions.UserExistsException;
import com.app.exceptions.UserNotRegisteredException;
import com.app.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserServices implements IUserServices{
    @Autowired
    UserRepository userRepository;


    public boolean addUser(UserModel obj) throws RuntimeException
    {   /*
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\."+
            "[a-zA-Z0-9_+&*-]+)*@" +
            "(?:[a-zA-Z0-9-]+\\.)+[a-z" +
            "A-Z]{2,7}$";

        if(obj.getName()=="")
        {
            throw new UserDetailsMissingException("Please Enter Name");
        }
        if(obj.getEmail()=="")
        {
            throw new UserDetailsMissingException("Please Enter Email");
        }
        Pattern pat = Pattern.compile(emailRegex);
        if(!pat.matcher(obj.getEmail()).matches())
        {
            throw new UserDetailsMissingException("Email not valid");
        }
        */

        Optional<UserModel> user =userRepository.findByEmail(obj.getEmail());
        if(user.isPresent()){
            throw new UserExistsException("Account already exists with this email");
        }


        userRepository.save(obj);
        return true;
    }
    public List<UserModel> getAllUsers() {
        return userRepository.findAll();
    }

    public boolean updateUserRole(String email, String newRole) {
        UserModel user = userRepository.getUserByEmail(email);
        if (user != null) {
            user.setRole(newRole);
            userRepository.save(user);
            return true;
        }
        return false;
    }


}

