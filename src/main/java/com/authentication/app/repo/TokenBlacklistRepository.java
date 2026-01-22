package com.authentication.app.repo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public class TokenBlacklistRepository {

    private final JdbcTemplate jdbcTemplate;

    public TokenBlacklistRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void revokeToken(String token){
        jdbcTemplate.update("INSERT INTO revoked_tokens (token , revoked_at ) VALUES (? , ?)", token , LocalDateTime.now());
    }

    public boolean isTokenRevoked(String token){
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM revoked_tokens WHERE token = ?", Integer.class, token);
        return count != null && count > 0;
    }
}
