package com.app.Consumer;


import com.app.entities.UserModel;
import com.app.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

 

@Service
public class UserConsumer {

 

    @Autowired
    private UserRepository userRepository;

 

    // Kafka topic names
    private static final String NEW_USER_TOPIC = "new_user_topic";
    private static final String UPDATE_USER_ROLE_TOPIC = "update_user_role_topic";

 

    @KafkaListener(topics = NEW_USER_TOPIC, groupId = "user_group")
    public void consumeNewUser(UserModel newUser) {
        // Add your logic to process the new user here
        // For example, you can save the user to the database or perform any other business logic
        userRepository.save(newUser);
        System.out.println("New user consumed: " + newUser);
    }

 

    @KafkaListener(topics = UPDATE_USER_ROLE_TOPIC, groupId = "user_group")
    public void consumeUpdateUserRole(UserModel updatedUser) {
        // Add your logic to process the updated user role here
        // For example, you can update the user's role in the database or perform any other business logic
        userRepository.save(updatedUser);
        System.out.println("User role update consumed: " + updatedUser);
    }
}