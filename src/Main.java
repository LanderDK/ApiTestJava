import java.util.Scanner;

import javax.swing.JOptionPane;

public class Main {

	public static void main(String[] args) {
		API.OnProgramStart.Initialize("APP NAME", "SECRET", "VERSION");

		System.out.println("\n[1] Login");
		System.out.println("[2] Register");
		if (!API.ApplicationSettings.freeMode) {
			System.out.println("[3] Extend Subscription");
		}
		System.out.print("\nOption: ");
		Scanner scanner = new Scanner(System.in);
		String option = scanner.nextLine();

		if (option.equals("1")) {
			System.out.print("\nUsername: ");
			String username = scanner.nextLine();
			System.out.print("\nPassword: ");
			String password = scanner.nextLine();

			if (API.login(username, password)) {
				JOptionPane.showMessageDialog(null, "Successfully Logged In!", API.OnProgramStart.Name,
						JOptionPane.INFORMATION_MESSAGE);
				System.out.println("ID: " + API.User.ID);
				System.out.println("Username: " + API.User.username);
				System.out.println("Email: " + API.User.email);
				System.out.println("Subscription Expiry: " + API.User.expiry);
				System.out.println("HWID: " + API.User.hwid);
				System.out.println("Last Login: " + API.User.lastLogin);
				System.out.println("IP: " + API.User.ip);
				scanner.nextLine();
				scanner.close();
				//Do code that you want after login
			} else {
				System.exit(0);
			}
		} else if (option.equals("2")) {
			System.out.print("\nUsername: ");
			String username = scanner.nextLine();
			System.out.print("\nPassword: ");
			String password = scanner.nextLine();
			System.out.print("\nEmail: ");
			String email = scanner.nextLine();
			String license = "N/A";
			if (!API.ApplicationSettings.freeMode) {
				System.out.print("\nLicense: ");
				license = scanner.nextLine();
			}

			if (API.register(username, password, email, license)) {
				JOptionPane.showMessageDialog(null, "Successfully Registered!", API.OnProgramStart.Name,
						JOptionPane.INFORMATION_MESSAGE);
				scanner.nextLine();
				scanner.close();
			} else {
				System.exit(0);
			}
		}
		if (!API.ApplicationSettings.freeMode) {
			if (option.equals("3")) {
				System.out.print("\nUsername: ");
				String username = scanner.nextLine();
				System.out.print("\nPassword: ");
				String password = scanner.nextLine();
				System.out.print("\nLicense: ");
				String license = scanner.nextLine();

				if (API.extendSub(username, password, license)) {
					JOptionPane.showMessageDialog(null, "Successfully Extended Your Subscription!",
							API.OnProgramStart.Name, JOptionPane.INFORMATION_MESSAGE);
					scanner.nextLine();
					scanner.close();
				} else {
					System.exit(0);
				}
			}
		}
	}

}
