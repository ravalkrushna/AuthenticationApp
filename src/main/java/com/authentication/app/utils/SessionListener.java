package com.authentication.app.utils;

import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

@WebListener
public class SessionListener implements HttpSessionListener {

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        SessionStore.add(event.getSession());
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        HttpSession session = event.getSession();

        Long userId = (Long) session.getAttribute("USER_ID");
        if (userId != null) {
            SessionRegistry.remove(userId, session.getId());
        }

        SessionStore.remove(session.getId());
    }
}
