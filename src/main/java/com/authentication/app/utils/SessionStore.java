package com.authentication.app.utils;

import jakarta.servlet.http.HttpSession;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class SessionStore {

    private static final Map<String, HttpSession> sessions = new ConcurrentHashMap<>();

    public static void add(HttpSession session) {
        sessions.put(session.getId(), session);
    }

    public static void remove(String sessionId) {
        sessions.remove(sessionId);
    }

    public static HttpSession get(String sessionId) {
        return sessions.get(sessionId);
    }
}
