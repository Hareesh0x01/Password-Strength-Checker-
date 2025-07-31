import sys

def main():
    print("===== Password Strength Checker =====\n")
    print("1. Command Line Interface")
    print("2. Graphical User Interface")
    
    while True:
        choice = input("\nSelect an interface (1 or 2): ")
        
        if choice == '1':
            # Import and run CLI
            from password_cli import main as cli_main
            cli_main()
            break
        elif choice == '2':
            # Import and run GUI
            try:
                from password_gui import main as gui_main
                gui_main()
                break
            except ImportError:
                print("Error: Tkinter is not available. Please install it or use the CLI version.")
        else:
            print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()