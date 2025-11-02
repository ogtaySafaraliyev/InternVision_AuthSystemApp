package com.auth.controller;

import com.auth.dto.ChangePasswordRequest;
import com.auth.dto.ResetPasswordRequest;
import com.auth.model.User;
import com.auth.security.CustomUserDetails;
import com.auth.service.PasswordService;
import com.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class PasswordController {
    
    private final PasswordService passwordService;
    private final UserService userService;
    
    // Show change password form (for logged-in users)
    @GetMapping("/change-password")
    public String showChangePasswordForm(Model model) {
        model.addAttribute("changePasswordRequest", new ChangePasswordRequest());
        return "change-password";
    }
    
    // Handle change password
    @PostMapping("/change-password")
    public String changePassword(@Valid @ModelAttribute ChangePasswordRequest request,
                                BindingResult result,
                                @AuthenticationPrincipal CustomUserDetails userDetails,
                                Model model,
                                RedirectAttributes redirectAttributes) {
        
        if (result.hasErrors()) {
            return "change-password";
        }
        
        try {
            passwordService.changePassword(
                userDetails.getUser(),
                request.getCurrentPassword(),
                request.getNewPassword(),
                request.getConfirmPassword()
            );
            
            redirectAttributes.addFlashAttribute("success", "Password changed successfully!");
            return "redirect:/home";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "change-password";
        }
    }
    
    // Show forgot password form
    @GetMapping("/forgot-password")
    public String showForgotPasswordForm(Model model) {
        model.addAttribute("resetPasswordRequest", new ResetPasswordRequest());
        return "forgot-password";
    }
    
    // Handle forgot password (generate reset token)
    @PostMapping("/forgot-password")
    public String forgotPassword(@Valid @ModelAttribute ResetPasswordRequest request,
                                BindingResult result,
                                Model model) {
        
        if (result.hasErrors()) {
            return "forgot-password";
        }
        
        try {
            String resetToken = passwordService.generateResetToken(request.getEmail());
            
            // In a real application, you would send this token via email
            // For now, we'll display it on the page for testing
            model.addAttribute("success", "Reset token generated! (In production, this would be sent via email)");
            model.addAttribute("resetToken", resetToken);
            model.addAttribute("email", request.getEmail());
            
            return "forgot-password-success";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "forgot-password";
        }
    }
    
    // Show reset password form
    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam("token") String token,
                                       @RequestParam("email") String email,
                                       Model model) {
        
        model.addAttribute("token", token);
        model.addAttribute("email", email);
        model.addAttribute("resetPasswordRequest", new ResetPasswordRequest());
        return "reset-password";
    }
    
    // Handle reset password
    @PostMapping("/reset-password")
    public String resetPassword(@Valid @ModelAttribute ResetPasswordRequest request,
                               BindingResult result,
                               @RequestParam("token") String token,
                               @RequestParam("email") String email,
                               Model model,
                               RedirectAttributes redirectAttributes) {
        
        if (result.hasErrors()) {
            model.addAttribute("token", token);
            model.addAttribute("email", email);
            return "reset-password";
        }
        
        try {
            passwordService.resetPassword(email, token, request.getNewPassword(), request.getConfirmPassword());
            
            redirectAttributes.addFlashAttribute("success", "Password reset successfully! Please login with your new password.");
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("token", token);
            model.addAttribute("email", email);
            return "reset-password";
        }
    }
}