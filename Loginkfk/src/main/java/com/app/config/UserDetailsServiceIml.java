package com.app.config;

import com.app.entities.UserModel;
import com.app.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceIml implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //featching user from database
        UserModel userModel=userRepository.getUserByEmail(username);
        if(userModel==null){
            throw new UsernameNotFoundException("Account not found with this email");
        }
        CustomUserDetails customUserDetails=new CustomUserDetails(userModel);
        return customUserDetails;
    }
}
