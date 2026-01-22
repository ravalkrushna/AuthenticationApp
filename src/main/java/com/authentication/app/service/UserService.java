package com.authentication.app.service;


import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import com.authentication.app.model.dao.UserDao;
import com.authentication.app.repo.UserRepository;
import com.authentication.app.utils.EmailUtil;
import com.authentication.app.utils.OtpUtil;
import com.authentication.app.security.JwtUtil;


@Service
public class UserService {

    private final UserRepository userRepo;
    private final EmailUtil emailUtil;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserService(
            UserRepository userRepo,
            EmailUtil emailUtil,
            JwtUtil jwtUtil
    ) {
        this.userRepo = userRepo;
        this.emailUtil = emailUtil;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public void registerUser(String email, String password) {

        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already in use");
        }

        UserDao user = new UserDao();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
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

    // 🔐 LOGIN CORE
    public String authenticateAndGenerateToken(String email, String password) {

        UserDao user = userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("User not verified");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        return jwtUtil.generateToken(user.getEmail());
    }

    public void changePassword(String email, String oldPassword, String newPassword) {

        UserDao user = userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new IllegalArgumentException("Old password incorrect");
        }

        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new IllegalArgumentException("New password cannot be same");
        }

        userRepo.updatePassword(user.getId(), passwordEncoder.encode(newPassword));
    }

    public void resetPassword(String email, String otp, String newPassword) {

        UserDao user = userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getOtp().equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP");
        }

        if (user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("OTP expired");
        }

        userRepo.updatePasswordAndClearOtp(
                email,
                passwordEncoder.encode(newPassword)
        );
    }

    public void sendForgetPasswordOtp(String email) {

        userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String otp = OtpUtil.generateOtp();
        userRepo.updateOtp(email, otp, LocalDateTime.now().plusMinutes(10));
        emailUtil.sendOtpEmail(email, otp);
    }
}
