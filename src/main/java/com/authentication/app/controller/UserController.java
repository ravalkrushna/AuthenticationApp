package com.authentication.app.controller;

import com.authentication.app.model.dto.*;
import com.authentication.app.utils.SessionRegistry;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.app.model.dao.UserDao;
import com.authentication.app.service.UserService;
import com.authentication.app.utils.SessionUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
	public ResponseEntity<?> signup(@RequestBody RegisterRequest request) {
		userService.registerUser(request.getEmail(), request.getPassword());
		return ResponseEntity.ok("OTP sent successfully");
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(
			@Valid @RequestBody LoginRequest loginRequest,
			HttpServletRequest httpRequest,
			HttpServletResponse response) {

		UserDao user = userService.loginUser(
				loginRequest.getEmail(),
				loginRequest.getPassword());

		Long userId = user.getId();

		if (!SessionRegistry.canLogin(userId)) {
			return ResponseEntity
					.status(403)
					.body("Too many active sessions");
		}

		HttpSession session = httpRequest.getSession(true);
		session.setAttribute("USER_ID", userId);

		SessionRegistry.add(userId, session.getId());

		Cookie cookie = new Cookie("USER_EMAIL", user.getEmail());
		cookie.setHttpOnly(true);
		cookie.setPath("/");
		cookie.setMaxAge(10 * 60);
		response.addCookie(cookie);

		return ResponseEntity.ok("Login successful");
	}

	@PostMapping("/verifyotp")
	public ResponseEntity<String> verifyOtp(@Valid @RequestBody OtpRequest otp) {
		userService.verifyOtp(otp.getEmail(), otp.getOtp());
		return ResponseEntity.ok("Email verified successfully");
	}

	@GetMapping("/session-check")
	public ResponseEntity<String> sessionCheck(HttpSession session) {
		if (session.getAttribute("USER_ID") == null) {
			return ResponseEntity.status(401).body("No active session");
		}
		return ResponseEntity.ok("Session active");
	}

	@GetMapping("/read-cookie")
	public ResponseEntity<String> readCookie(
			@CookieValue(value = "USER_EMAIL", required = false) String email) {

		if (email == null) {
			return ResponseEntity.status(401).body("Cookie not found");
		}
		return ResponseEntity.ok("Cookie value: " + email);
	}

	@PostMapping("/change-password")
	public ResponseEntity<String> changePassword(
			@Valid @RequestBody ChangePasswordRequest request,
			HttpSession session) {

		Long userId = (Long) session.getAttribute("USER_ID");
		if (userId == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}

		userService.changePassword(
				userId,
				request.getOldPassword(),
				request.getNewPassword());

		return ResponseEntity.ok("Password changed successfully");
	}

	@PostMapping("/forgotpassword")
	public ResponseEntity<String> forgotPassword(@RequestBody RegisterRequest request){
		userService.sendForgetPasswordOtp(request.getEmail());
		return ResponseEntity.ok("OTP sent to email");
	}

	@PostMapping("/resetpassword")
	public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
		userService.resetPassword(request.getEmail(), request.getOtp(), request.getNewPassword());
		return ResponseEntity.ok("Password reset successfully");
	}

	@PostMapping("/logout")
	public ResponseEntity<String> logout(HttpServletRequest request , HttpServletResponse response){
		HttpSession session = request.getSession(false);

		if(session != null){
			session.invalidate();
		}
		Cookie cookie = new Cookie("USER_EMAIL" , null);
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);

		return ResponseEntity.ok("Logged out successfully");
	}
}
