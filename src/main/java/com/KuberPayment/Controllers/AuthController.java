package com.KuberPayment.Controllers;

import com.KuberPayment.Entities.AppUser;
import com.KuberPayment.Repositories.UserRepository;
import com.KuberPayment.Services.TwoFactorService;

import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
public class AuthController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private TwoFactorService twoFAService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // -------------------- REGISTRATION -----------------------

    @GetMapping("/register")
    public String showRegister(Model model) {
        model.addAttribute("user", new AppUser());
        return "register";
    }

    @PostMapping("/register")
    public String doRegister(@ModelAttribute("user") AppUser user,
                             @RequestParam String confirmPassword,
                             HttpSession session,
                             Model model) {

        if (!user.getPassword().equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match.");
            return "register";
        }

        Optional<AppUser> existingUser = userRepo.findByEmail(user.getEmail());
        if (existingUser.isPresent()) {
            model.addAttribute("error", "User with this email already exists.");
            return "register";
        }

        user.setSecret(twoFAService.generateSecretKey());
        user.set2FAEnabled(true);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);

        session.setAttribute("user", user);
        session.setAttribute("registering", true); // Flag for registration
        return "redirect:/otp";
    }

    // --------------------- LOGIN ------------------------

    @GetMapping("/login")
    public String showLogin() {
        return "login";
    }

    @GetMapping("/handle-2fa")
    public String handleLoginWith2FA(HttpSession session) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login?error=auth";
        }

        String email = authentication.getName();
        Optional<AppUser> optionalUser = userRepo.findByEmail(email);

        if (optionalUser.isEmpty()) {
            return "redirect:/login?error=userNotFound";
        }

        AppUser user = optionalUser.get();

        if (user.is2FAEnabled()) {
            session.setAttribute("user", user);
            // Don't set "registering" flag here
            return "redirect:/otp";
        }

        session.setAttribute("loggedInUser", user);
        return "redirect:/home";
    }

    // --------------------- OTP ------------------------

    @GetMapping("/otp")
    public String showOtpPage(HttpSession session, Model model) {
        AppUser user = (AppUser) session.getAttribute("user");
        if (user == null) return "redirect:/login";

        Boolean isFromRegister = (Boolean) session.getAttribute("registering");

        if (Boolean.TRUE.equals(isFromRegister)) {
            model.addAttribute("qrUrl", twoFAService.getQRBarcodeURL(user.getEmail(), user.getSecret()));
        }

        return "otp";
    }

    @PostMapping("/otp")
    public String verifyOtp(@RequestParam int code, HttpSession session, Model model) {
        AppUser user = (AppUser) session.getAttribute("user");
        if (user == null) return "redirect:/login";

        boolean isValid = twoFAService.verifyOTP(user.getSecret(), code);
        if (isValid) {
            session.removeAttribute("user");
            session.removeAttribute("registering");
            session.setAttribute("loggedInUser", user);
            return "redirect:/home";
        }

        model.addAttribute("error", "Invalid OTP. Please try again.");

        Boolean isFromRegister = (Boolean) session.getAttribute("registering");
        if (Boolean.TRUE.equals(isFromRegister)) {
            model.addAttribute("qrUrl", twoFAService.getQRBarcodeURL(user.getEmail(), user.getSecret()));
        }

        return "otp";
    }

    // -------------------- HOME + LOGOUT -----------------------

    @GetMapping("/home")
    public String home(HttpSession session, Model model) {
        AppUser user = (AppUser) session.getAttribute("loggedInUser");
        if (user == null) return "redirect:/login";

        model.addAttribute("email", user.getEmail());
        return "home";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login?logout";
    }
}
