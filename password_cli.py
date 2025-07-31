from password_checker import PasswordChecker

def main():
    print("===== Password Strength Checker =====\n")
    
    checker = PasswordChecker()
    
    while True:
        password = input("Enter a password to check (or 'q' to quit): ")
        
        if password.lower() == 'q':
            break
        
        result = checker.check_strength(password)
        
        print(f"\nPassword Strength: {result['level']}")
        print(f"Score: {result['score']}/100")
        
        if result['suggestions']:
            print("\nSuggestions to improve your password:")
            for suggestion in result['suggestions']:
                print(f"- {suggestion}")
        else:
            print("\nYour password meets all the criteria!")
        
        # Show hash for educational purposes
        hashed = checker.hash_password(password)
        print(f"\nPassword hash (SHA-256): {hashed[:15]}...")
        
        print("\n" + "-" * 40 + "\n")

if __name__ == "__main__":
    main()