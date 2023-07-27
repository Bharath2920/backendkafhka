package com.app.controller;

import com.app.config.CustomUserDetails;
import com.app.config.jwt.JwtUtils;
import com.app.entities.UserModel;
import com.app.repo.UserRepository;
import com.app.response.loginResponse;
import com.app.services.IUserServices;
import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class UserController {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    IUserServices userServices;

    @Autowired
    UserRepository userRepository;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;
   /*
    To Test if the DB is working
    @GetMapping("/test")
    @ResponseBody
    public String test(){
        User user=new User();
        user.setName("Test");
        user.setEmail("Test@test.in");
        user.setPassword("1234");

        userRepository.save(user);
        return "Working";
    }
    //Login

    */
    @GetMapping("/")
    public String Home(){
        return "home";
    }






    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> register(@RequestBody UserModel userDetails)
    {
        Map<String, String> response = new HashMap<>();
        try
        {    userDetails.setPassword(passwordEncoder.encode(userDetails.getPassword()));
        	userDetails.setRole("ROLE_"+userDetails.getRole());
            if(userServices.addUser(userDetails))
            {
                response.put("Status","True");
                //response.put("SessionID","1234");
            }
        }
        catch(Exception e)
        {
            response.put("Status","Fail");
            response.put("Error",e.getMessage());
            return new ResponseEntity<Map<String, String>>(response, HttpStatus.CONFLICT);
        }
        return new ResponseEntity<Map<String, String>>(response, HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser( @RequestBody Map<String,String> loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.get("email"), loginRequest.get("password")));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        UserModel res = userRepository.getUserByEmail(loginRequest.get("email"));

        loginResponse response=new loginResponse(res.getId(), res.getName(), res.getEmail(), res.getRole());

//        Cookie newCookie =new Cookie(HttpHeaders.SET_COOKIE,jwtCookie.toString())  ;
//
//        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
//                .body(response);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, jwtCookie.toString()); // Manually create the Set-Cookie header

        return ResponseEntity.ok().headers(headers).body(response);
    }


    @GetMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(Map.of("Message","You've been signed out!"));
    }

    @GetMapping("/admin/view")
    public List<UserModel> view() {
        return userServices.getAllUsers();
    }
    @PostMapping("/update")
    public boolean updateUserRole(@RequestBody Map<String,String> res) {
        String email=res.get("email");
        String newRole=res.get("role");;
        return userServices.updateUserRole(email, newRole);
    }


}
