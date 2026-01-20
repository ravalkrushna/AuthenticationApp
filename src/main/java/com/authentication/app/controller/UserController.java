package com.authentication.app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.app.model.dao.UserDao;
import com.authentication.app.model.dto.LoginRequest;
import com.authentication.app.model.dto.OtpRequest;
import com.authentication.app.model.dto.RegisterRequest;
import com.authentication.app.service.UserService;
import com.authentication.app.utils.SessionUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/users/auth")
public class UserController {
	
	private final UserService userService;
	
	public UserController(UserService userService) {
		this.userService = userService;
	}
	
	@PostMapping("/signup")
	public ResponseEntity<?> userSignup(@RequestBody RegisterRequest request) {
	    try {
	        userService.registerUser(request.getEmail(), request.getPassword());
	        return ResponseEntity.ok("OTP sent successfully");
	    } catch (IllegalArgumentException e) {
	        return ResponseEntity.badRequest().body(e.getMessage());
	    }
	}

	@PostMapping("/login")
	public ResponseEntity<String> userLogin(@Valid @RequestBody LoginRequest request , HttpServletRequest httprequest) {
		UserDao user = userService.loginUser(request.getEmail(), request.getPassword());
		SessionUtil.createSession(httprequest, user.getId());
		return ResponseEntity.ok("Login successful.");		
	}
	
	@PostMapping("/verifyotp")
	public ResponseEntity<String> verifyOtp(@Valid @RequestBody OtpRequest otp) {
		userService.verifyOtp(otp.getEmail(), otp.getOtp());
		return ResponseEntity.ok("Email verified successfully.");
	}
	
	@GetMapping("/session-check")
	public ResponseEntity<String> sessionCheck(HttpSession session) {

	    if (session.getAttribute("USER_ID") == null) {
	        return ResponseEntity.status(401).body("No active session");
	    }

	    return ResponseEntity.ok("Session active");
	}

}
