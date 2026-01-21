package com.authentication.app.utils;

import java.util.*;

public class SessionRegistry {

    private static final Map<Long , Set<String>> store = new HashMap<>();

    private static final int MAX_SESSIONS_PER_USER = 2;

    public static boolean canLogin(Long userId){
        return store.getOrDefault(userId , Set.of()).size() < MAX_SESSIONS_PER_USER;
    }

    public static void add(Long userId , String sessionId){
        store.computeIfAbsent(userId , k -> new HashSet<>()).add(sessionId);
    }

    public static void remove(Long userId , String sessionId){
        Set<String> sessions = store.get(userId);
        if(sessions != null){
            sessions.remove(sessionId);
            if(sessions.isEmpty()){
                store.remove(userId);
            }
        }
    }
}
