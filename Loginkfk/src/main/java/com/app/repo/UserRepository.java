package com.app.repo;

import com.app.entities.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;


public interface UserRepository extends JpaRepository<UserModel, Integer> {

    Optional<UserModel> findByEmail(String email);
    //@Query("select u from user u where u.email=:email")
    //UserModel getUserByEmailId(@Param("email") String email);

    UserModel getUserByEmail(@Param("email") String email);
}
