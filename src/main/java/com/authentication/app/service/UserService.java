package com.authentication.app.service;

import com.authentication.app.utils.SessionRegistry;
import com.authentication.app.utils.SessionStore;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import com.authentication.app.model.dao.UserDao;
import com.authentication.app.repo.UserRepository;
import com.authentication.app.utils.EmailUtil;
import com.authentication.app.utils.OtpUtil;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final EmailUtil emailUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepo, EmailUtil emailUtil) {
        this.userRepo = userRepo;
        this.emailUtil = emailUtil;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public void registerUser(String email, String password) {

        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already in use");
        }

        UserDao user = new UserDao();
        user.setEmail(email);
        user.setPassword(new BCryptPasswordEncoder().encode(password));
        user.setEnabled(false);

        String otp = OtpUtil.generateOtp();
        user.setOtp(otp);
        user.setOtpExpiry(LocalDateTime.now().plusMinutes(10));

        userRepo.saveUser(user);

        emailUtil.sendOtpEmail(email, otp);
    }

    public void verifyOtp(String email, String otp) {

        UserDao user = userRepo.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.isEnabled()) {
            throw new IllegalArgumentException("User already verified");
        }

        if (!user.getOtp().equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP");
        }

        if (user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("OTP expired");
        }

        userRepo.updateVerification(email);
    }


    public UserDao loginUser(String email, String password) {

        UserDao user = userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("User not verified");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }
        
        return user;
    }

    public void changePassword(
            Long userId,
            String oldPassword,
            String newPassword) {

        UserDao user = userRepo.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new IllegalArgumentException("Old password is incorrect");
        }

        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new IllegalArgumentException("New password cannot be same as old");
        }

        String encoded = passwordEncoder.encode(newPassword);
        userRepo.updatePassword(userId, encoded);

        invalidateAllSessions(userId);
    }

    public void resetPassword(String email , String otp , String newPassword){
        UserDao user = userRepo.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getOtp().equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP");
        }

        if (user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("OTP expired");
        }

        String encoded = passwordEncoder.encode(newPassword);
        userRepo.updatePassword(user.getId(), encoded);
    }

    public void sendForgetPasswordOtp(String email) {
        userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String otp = OtpUtil.generateOtp();

        userRepo.updateOtp(email , otp , LocalDateTime.now().plusMinutes(10));

        emailUtil.sendOtpEmail(email, otp);
    }

    public void invalidateAllSessions(Long userId) {

        for (String sessionId : SessionRegistry.getSessions(userId)) {
            HttpSession session = SessionStore.get(sessionId);
            if (session != null) {
                session.invalidate();
            }
        }
    }

}
