import re
import hashlib

# List of common passwords to check against
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "admin", "welcome",
    "1234567", "12345678", "abc123", "football", "monkey",
    "letmein", "111111", "mustang", "access", "shadow",
    "master", "michael", "superman", "696969", "123123",
    "batman", "trustno1", "baseball", "dragon", "sunshine"
]

class PasswordChecker:
    def __init__(self):
        pass
    
    def check_strength(self, password):
        """Evaluate the strength of a password and return a score, level, and suggestions."""
        score = 0
        suggestions = []
        
        # Check length (minimum 8 characters)
        if len(password) >= 8:
            score += 20
        else:
            suggestions.append("Use at least 8 characters")
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 20
        else:
            suggestions.append("Add at least one uppercase letter")
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 20
        else:
            suggestions.append("Add at least one lowercase letter")
        
        # Check for digits
        if re.search(r'\d', password):
            score += 20
        else:
            suggestions.append("Add at least one digit")
        
        # Check for special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        else:
            suggestions.append("Add at least one special character")
        
        # Check against common passwords
        if password.lower() in COMMON_PASSWORDS:
            score = max(0, score - 40)  # Significant penalty for common passwords
            suggestions.append("Your password is too common and easily guessable")
        
        # Determine strength level
        if score < 40:
            level = "Weak"
        elif score < 80:
            level = "Medium"
        else:
            level = "Strong"
        
        return {
            "score": score,
            "level": level,
            "suggestions": suggestions
        }
    
    def hash_password(self, password):
        """Hash the password using SHA-256 to simulate safe storage."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def check_pwned(self, password):
        """Check if password has been exposed in data breaches using haveibeenpwned API.
        Note: This is a placeholder for the advanced feature.
        """
        # This would require API integration with haveibeenpwned
        # For now, we'll just return a placeholder message
        return "API integration not implemented yet"