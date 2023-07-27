package com.app.services;	
	
import java.util.List;

import org.apache.el.stream.Optional;

// Imports...

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.app.entities.UserModel;
import com.app.exceptions.UserExistsException;
import com.app.repo.UserRepository;

 

@Service
public class kafkaservice implements IUserServices {

 

    @Autowired
    private UserRepository userRepository;

 

    @Autowired
    private KafkaTemplate<String, UserModel> kafkaTemplate;

 

    // Kafka topic names
    private static final String NEW_USER_TOPIC = "new_user_topic";
    private static final String UPDATE_USER_ROLE_TOPIC = "update_user_role_topic";

 

    public boolean addUser(UserModel obj) throws RuntimeException
    {
        // Existing code to check if user already exists
        java.util.Optional<UserModel> user = userRepository.findByEmail(obj.getEmail());
        
        if (user.isPresent())
        {
            throw new UserExistsException("Account already exists with this email");
        }

 

        // Save the new user to the database
        userRepository.save(obj);

 

        // Publish a Kafka message for adding a new user
        kafkaTemplate.send(NEW_USER_TOPIC, obj);
        return true;
    }

 

    public List<UserModel> getAllUsers() {
        return userRepository.findAll();
    }

 

    public boolean updateUserRole(String email, String newRole) {
        UserModel user = userRepository.getUserByEmail(email);
        if (user != null) {
            // Update the user's role in the database
            user.setRole(newRole);
            userRepository.save(user);

 

            // Publish a Kafka message for updating the user role
            kafkaTemplate.send(UPDATE_USER_ROLE_TOPIC, user);
            return true;
        }
        return false;
    }
}

//status 
