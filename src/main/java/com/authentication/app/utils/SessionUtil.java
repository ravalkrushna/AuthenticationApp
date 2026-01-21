package com.authentication.app.utils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class SessionUtil {
	
	public static void createSession(HttpServletRequest request , Long userId) {
		HttpSession session = request.getSession(true);
		session.setAttribute(SessionConstants.USER_ID, userId);
		session.setMaxInactiveInterval(10 * 60);
	}
	
	public static Long getUserId(HttpSession session) {
		return (Long) session.getAttribute(SessionConstants.USER_ID);
	}
		
	public static boolean isLoggedIn(HttpSession session) {
		return getUserId(session) != null;
	}
}
