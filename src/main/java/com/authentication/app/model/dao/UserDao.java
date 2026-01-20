package com.authentication.app.model.dao;

import java.time.LocalDateTime;

public class UserDao {

	private Long id;
	private String email;
	private String password;
	private boolean enabled;
	private String otp;
	private LocalDateTime otpExpiry;

	public Long getId() { return id; }
	public void setId(Long id) { this.id = id; }

	public String getEmail() { return email; }
	public void setEmail(String email) { this.email = email; }

	public String getPassword() { return password; }
	public void setPassword(String password) { this.password = password; }

	public boolean isEnabled() { return enabled; }
	public void setEnabled(boolean enabled) { this.enabled = enabled; }

	public String getOtp() { return otp; }
	public void setOtp(String otp) { this.otp = otp; }

	public LocalDateTime getOtpExpiry() { return otpExpiry; }
	public void setOtpExpiry(LocalDateTime otpExpiry) { this.otpExpiry = otpExpiry; }
}
