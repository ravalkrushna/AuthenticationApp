package com.authentication.app.utils;

public class OtpUtil {
	private OtpUtil() {
	
	}
	
	public static String generateOtp() {
		return String.valueOf((int)(Math.random() * 900000) + 100000);
	}
}
