# Password Strength Checker

A Python application that evaluates the strength of passwords based on security criteria and provides feedback and improvement suggestions.

## Features

- Evaluates password strength based on multiple criteria:
  - Minimum length of 8 characters
  - Presence of uppercase letters
  - Presence of lowercase letters
  - Presence of digits
  - Presence of special characters
  - Check against common passwords
- Provides a strength rating (Weak/Medium/Strong)
- Offers specific suggestions for improvement
- Displays a strength score out of 100
- Shows a SHA-256 hash of the password (for educational purposes)
- Available in both CLI and GUI interfaces

## Requirements

- Python 3.6 or higher
- Tkinter (for GUI version)

## Usage

### Running the Application

```
python main.py
```

This will present you with options to choose between the command-line interface or the graphical user interface.

### Command Line Interface

To directly run the CLI version:

```
python password_cli.py
```

### Graphical User Interface

To directly run the GUI version:

```
python password_gui.py
```

## How It Works

The password checker evaluates passwords based on the following criteria:

1. **Length**: Passwords should be at least 8 characters long
2. **Character Variety**: Passwords should include a mix of:
   - Uppercase letters (A-Z)
   - Lowercase letters (a-z)
   - Digits (0-9)
   - Special characters (!@#$%^&*(),.?":{}|<>)
3. **Common Password Check**: Passwords are checked against a list of commonly used passwords

Each criterion contributes to the overall strength score, which determines whether the password is classified as Weak, Medium, or Strong.

## Future Enhancements

- Integration with the Have I Been Pwned API to check if passwords have been exposed in data breaches
- Storage of previously tested passwords in a local encrypted file
- Additional password generation suggestions

## License

This project is open source and available for educational and personal use.