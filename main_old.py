def execute_command(command):
    if command == '1':
        print("Executing Command 1...")
        # Add followup for Command 1 here
    elif command == '2':
        print("Executing Command 2...")
        # Add followup for Command 2 here
    else:
        print("Invalid command. Please try again.")


def main():
    print("")
    print("Welcome to the ARP / DNS poisoning tool. Please type a number to start poisoning.")
    print("1. ARP poisoning")
    print("2. DNS poisoning")
    print("")
    print("Type 'q' or 'quit' to exit.")

    while True:
        user_input = input("Select a command: ")

        if user_input.lower() == 'q' or user_input.lower() == 'quit':
            print("Exiting the tool...")
            break

        execute_command(user_input)


if __name__ == '__main__':
    main()
