import tkinter as tk
from tkinter import ttk, messagebox
import re
import random
import string
from password_checker import PasswordChecker

class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("600x550")
        self.root.resizable(False, False)
        
        # Set theme colors
        self.bg_color = "#f0f0f0"
        self.title_color = "#2c3e50"
        self.weak_color = "#e74c3c"
        self.medium_color = "#f39c12"
        self.strong_color = "#2ecc71"
        self.criteria_met_color = "#2ecc71"
        self.criteria_not_met_color = "#e74c3c"
        
        self.checker = PasswordChecker()
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame, 
            text="Password Strength Checker", 
            font=("Arial", 18, "bold"),
            fg=self.title_color,
            bg=self.bg_color,
            pady=10
        )
        title_label.pack()
        
        # Password entry frame
        entry_frame = tk.Frame(main_frame, bg=self.bg_color, pady=10)
        entry_frame.pack(fill=tk.X)
        
        password_label = tk.Label(
            entry_frame, 
            text="Enter Password:", 
            font=("Arial", 12, "bold"),
            bg=self.bg_color
        )
        password_label.pack(anchor="w")
        
        self.password_var = tk.StringVar()
        self.password_var.trace("w", self.on_password_change)
        
        entry_container = tk.Frame(entry_frame, bg=self.bg_color)
        entry_container.pack(fill=tk.X, pady=5)
        
        self.password_entry = tk.Entry(
            entry_container, 
            textvariable=self.password_var,
            font=("Arial", 12),
            show="•",
            width=40,
            bd=2,
            relief=tk.GROOVE
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Generate password button
        generate_btn = tk.Button(
            entry_container,
            text="Generate",
            font=("Arial", 10),
            command=self.generate_password,
            bg="#3498db",
            fg="white",
            padx=10
        )
        generate_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Show/Hide password checkbox
        options_frame = tk.Frame(entry_frame, bg=self.bg_color)
        options_frame.pack(fill=tk.X, pady=5)
        
        self.show_password_var = tk.BooleanVar()
        show_password_check = tk.Checkbutton(
            options_frame, 
            text="Show Password", 
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            bg=self.bg_color
        )
        show_password_check.pack(side=tk.LEFT)
        
        # Strength meter frame
        meter_frame = tk.Frame(main_frame, bg=self.bg_color, pady=10)
        meter_frame.pack(fill=tk.X)
        
        strength_label = tk.Label(
            meter_frame, 
            text="Password Strength:", 
            font=("Arial", 12, "bold"),
            bg=self.bg_color
        )
        strength_label.pack(anchor="w")
        
        # Strength progress bar
        self.strength_meter = ttk.Progressbar(
            meter_frame, 
            orient="horizontal", 
            length=560, 
            mode="determinate"
        )
        self.strength_meter.pack(fill=tk.X, pady=5)
        
        # Strength level label
        self.strength_level = tk.Label(
            meter_frame, 
            text="", 
            font=("Arial", 14, "bold"),
            bg=self.bg_color
        )
        self.strength_level.pack(anchor="w")
        
        # Password criteria frame
        criteria_frame = tk.LabelFrame(main_frame, text="Password Criteria", font=("Arial", 11, "bold"), bg=self.bg_color, pady=10, padx=10)
        criteria_frame.pack(fill=tk.X, pady=10)
        
        # Create criteria indicators
        self.criteria_indicators = {}
        criteria_list = [
            ("length", "Length (8+ characters)"),
            ("uppercase", "Uppercase letters (A-Z)"),
            ("lowercase", "Lowercase letters (a-z)"),
            ("digits", "Digits (0-9)"),
            ("special", "Special characters (!@#$%^&*)"),
            ("common", "Not a common password")
        ]
        
        # Create a grid of criteria indicators
        for i, (key, text) in enumerate(criteria_list):
            row, col = divmod(i, 2)
            
            frame = tk.Frame(criteria_frame, bg=self.bg_color)
            frame.grid(row=row, column=col, sticky="w", pady=5, padx=10)
            
            indicator = tk.Canvas(frame, width=15, height=15, bg=self.bg_color, highlightthickness=0)
            indicator.create_oval(2, 2, 13, 13, fill=self.criteria_not_met_color, outline="")
            indicator.pack(side=tk.LEFT, padx=(0, 5))
            
            label = tk.Label(frame, text=text, bg=self.bg_color, font=("Arial", 10))
            label.pack(side=tk.LEFT)
            
            self.criteria_indicators[key] = indicator
        
        # Suggestions frame
        suggestions_frame = tk.Frame(main_frame, bg=self.bg_color, pady=10)
        suggestions_frame.pack(fill=tk.BOTH, expand=True)
        
        suggestions_label = tk.Label(
            suggestions_frame, 
            text="Suggestions:", 
            font=("Arial", 12),
            bg=self.bg_color
        )
        suggestions_label.pack(anchor="w")
        
        # Suggestions text area
        self.suggestions_text = tk.Text(
            suggestions_frame, 
            height=5, 
            width=50, 
            font=("Arial", 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.suggestions_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Hash display frame
        hash_frame = tk.Frame(main_frame, bg=self.bg_color, pady=10)
        hash_frame.pack(fill=tk.X)
        
        hash_label = tk.Label(
            hash_frame, 
            text="Password Hash (SHA-256):", 
            font=("Arial", 10),
            bg=self.bg_color
        )
        hash_label.pack(anchor="w")
        
        self.hash_var = tk.StringVar()
        hash_entry = tk.Entry(
            hash_frame, 
            textvariable=self.hash_var,
            font=("Arial", 10),
            state="readonly",
            width=40
        )
        hash_entry.pack(fill=tk.X, pady=5)
    
    def on_password_change(self, *args):
        password = self.password_var.get()
        
        if password:
            result = self.checker.check_strength(password)
            
            # Update strength meter
            self.strength_meter["value"] = result["score"]
            
            # Update strength level with color
            level = result["level"]
            if level == "Weak":
                color = self.weak_color
            elif level == "Medium":
                color = self.medium_color
            else:  # Strong
                color = self.strong_color
            
            self.strength_level.config(text=f"{level} ({result['score']}/100)", fg=color)
            
            # Update suggestions
            self.suggestions_text.config(state=tk.NORMAL)
            self.suggestions_text.delete(1.0, tk.END)
            
            if result["suggestions"]:
                for suggestion in result["suggestions"]:
                    self.suggestions_text.insert(tk.END, f"• {suggestion}\n")
            else:
                self.suggestions_text.insert(tk.END, "Your password meets all the criteria!")
            
            self.suggestions_text.config(state=tk.DISABLED)
            
            # Update hash
            hashed = self.checker.hash_password(password)
            self.hash_var.set(f"{hashed[:20]}...")
            
            # Update criteria indicators
            self.update_criteria_indicators(password, result)
        else:
            # Reset everything if password is empty
            self.strength_meter["value"] = 0
            self.strength_level.config(text="")
            self.suggestions_text.config(state=tk.NORMAL)
            self.suggestions_text.delete(1.0, tk.END)
            self.suggestions_text.config(state=tk.DISABLED)
            self.hash_var.set("")
            
            # Reset criteria indicators
            for indicator in self.criteria_indicators.values():
                indicator.itemconfig(1, fill=self.criteria_not_met_color)
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def update_criteria_indicators(self, password, result):
        # Update length indicator
        if len(password) >= 8:
            self.criteria_indicators["length"].itemconfig(1, fill=self.criteria_met_color)
        else:
            self.criteria_indicators["length"].itemconfig(1, fill=self.criteria_not_met_color)
        
        # Update uppercase indicator
        if re.search(r'[A-Z]', password):
            self.criteria_indicators["uppercase"].itemconfig(1, fill=self.criteria_met_color)
        else:
            self.criteria_indicators["uppercase"].itemconfig(1, fill=self.criteria_not_met_color)
        
        # Update lowercase indicator
        if re.search(r'[a-z]', password):
            self.criteria_indicators["lowercase"].itemconfig(1, fill=self.criteria_met_color)
        else:
            self.criteria_indicators["lowercase"].itemconfig(1, fill=self.criteria_not_met_color)
        
        # Update digits indicator
        if re.search(r'\d', password):
            self.criteria_indicators["digits"].itemconfig(1, fill=self.criteria_met_color)
        else:
            self.criteria_indicators["digits"].itemconfig(1, fill=self.criteria_not_met_color)
        
        # Update special characters indicator
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            self.criteria_indicators["special"].itemconfig(1, fill=self.criteria_met_color)
        else:
            self.criteria_indicators["special"].itemconfig(1, fill=self.criteria_not_met_color)
        
        # Update common password indicator
        from password_checker import COMMON_PASSWORDS
        if password.lower() in COMMON_PASSWORDS:
            self.criteria_indicators["common"].itemconfig(1, fill=self.criteria_not_met_color)
        else:
            self.criteria_indicators["common"].itemconfig(1, fill=self.criteria_met_color)
    
    def generate_password(self):
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*(),.?\":{}|<>"
        
        # Ensure at least one character from each set
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Add more random characters to reach a length of 12
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(8))
        
        # Shuffle the password characters
        random.shuffle(password)
        
        # Convert list to string and set it as the password
        generated_password = ''.join(password)
        self.password_var.set(generated_password)
        
        # Show a message
        messagebox.showinfo("Password Generated", "A strong password has been generated!")
        
        # Set focus to the password entry
        self.password_entry.focus()

def main():
    root = tk.Tk()
    app = PasswordStrengthGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()