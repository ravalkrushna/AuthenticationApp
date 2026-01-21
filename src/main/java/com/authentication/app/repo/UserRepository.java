package com.authentication.app.repo;

import com.authentication.app.model.dao.UserDao;

import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    private final JdbcTemplate jdbcTemplate;

    public UserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean existsByEmail(String email) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from users where email = ?",
                Integer.class,
                email
        );
        return count != null && count > 0;
    }

    public Optional<UserDao> findByEmail(String email) {
        return jdbcTemplate.query(
                "select * from users where email = ?",
                userRowMapper,
                email
        ).stream().findFirst();
    }

    public void saveUser(UserDao user) {
        jdbcTemplate.update(
            "insert into users (email, password, enabled, otp, otp_expiry) values (?,?,?,?,?)",
            user.getEmail(),
            user.getPassword(),
            user.isEnabled(),
            user.getOtp(),
            user.getOtpExpiry()
        );
    }

    public void updateVerification(String email) {
        jdbcTemplate.update(
            "UPDATE users SET enabled = true, otp = NULL, otp_expiry = NULL WHERE email = ?",
            email
        );
    }

    private final RowMapper<UserDao> userRowMapper = (rs, rowNum) -> {
        UserDao user = new UserDao();
        user.setId(rs.getLong("id"));
        user.setEmail(rs.getString("email"));
        user.setPassword(rs.getString("password"));
        user.setEnabled(rs.getBoolean("enabled"));
        user.setOtp(rs.getString("otp"));
        user.setOtpExpiry(
            rs.getTimestamp("otp_expiry") != null
                ? rs.getTimestamp("otp_expiry").toLocalDateTime()
                : null
        );
        return user;
    };

    public Optional<UserDao> findById(Long id) {
        return jdbcTemplate.query(
                "select * from users where id = ?",
                userRowMapper,
                id
        ).stream().findFirst();
    }

    public void updatePassword(Long id, String encodedPassword) {
        jdbcTemplate.update(
                "update users set password = ? where id = ?",
                encodedPassword,
                id
        );
    }

}
