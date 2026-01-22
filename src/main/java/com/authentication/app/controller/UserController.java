package com.authentication.app.controller;

import com.authentication.app.model.dto.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.authentication.app.service.UserService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/users/auth")
public class UserController {

	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	// REGISTER (UNCHANGED LOGIC)
	@PostMapping("/signup")
	public ResponseEntity<String> signup(@RequestBody RegisterRequest request) {
		userService.registerUser(request.getEmail(), request.getPassword());
		return ResponseEntity.ok("OTP sent successfully");
	}

	// LOGIN → RETURNS JWT
	@PostMapping("/login")
	public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest request) {
		String token = userService.authenticateAndGenerateToken(
				request.getEmail(),
				request.getPassword()
		);
		return ResponseEntity.ok(new JwtResponse(token));
	}

	@PostMapping("/verifyotp")
	public ResponseEntity<String> verifyOtp(@Valid @RequestBody OtpRequest otp) {
		userService.verifyOtp(otp.getEmail(), otp.getOtp());
		return ResponseEntity.ok("Email verified successfully");
	}

	// SECURED ENDPOINT
	@PostMapping("/changepassword")
	public ResponseEntity<String> changePassword(
			@Valid @RequestBody ChangePasswordRequest request,
			@AuthenticationPrincipal org.springframework.security.core.userdetails.User user
	) {
		userService.changePassword(
				user.getUsername(),
				request.getOldPassword(),
				request.getNewPassword()
		);
		return ResponseEntity.ok("Password changed successfully");
	}

	@PostMapping("/forgotpassword")
	public ResponseEntity<String> forgotPassword(@RequestBody RegisterRequest request) {
		userService.sendForgetPasswordOtp(request.getEmail());
		return ResponseEntity.ok("OTP sent to email");
	}

	@PostMapping("/resetpassword")
	public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
		userService.resetPassword(
				request.getEmail(),
				request.getOtp(),
				request.getNewPassword()
		);
		return ResponseEntity.ok("Password reset successfully");
	}
}
