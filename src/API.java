import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.awt.Desktop;
import java.io.*;
import org.json.JSONObject;
import javax.swing.JOptionPane;

public class API {

	static class Constants {
		static String apiUrl = "https://api.blitzware.xyz/api/";
		// static String apiUrl = "http://localhost:9000/api/";
		static boolean initialized = false;
		static boolean started = false;
		static boolean breached = false;
		static LocalDateTime timeSent = LocalDateTime.now();

		static String HWID() {
			String uuid = null;
			try {
				ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", "wmic csproduct get uuid");
				builder.redirectErrorStream(true);
				Process process = builder.start();

				BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
				StringBuilder output = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					output.append(line + "\n");
				}

				int exitCode = process.waitFor();
				if (exitCode == 0) {
					uuid = output.substring(output.indexOf("\n") + 1).trim();
				} else {
					System.out.println("Command execution failed with exit code: " + exitCode);
				}

			} catch (IOException | InterruptedException e) {
				e.printStackTrace();
			}
			return uuid;
		}

		static String IP() throws IOException {
			String url = "http://icanhazip.com";
			HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
			con.setRequestMethod("GET");
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8));
			String ip = in.readLine().trim();
			in.close();
			return ip;
		}
	}

	static class ApplicationSettings {
		static String id;
		static boolean status;
		static boolean hwidCheck;
		static boolean developerMode;
		static String programHash;
		static String version;
		static String downloadLink;
		static boolean freeMode;
		static boolean login;
		static String name;
		static boolean register;
		static String totalUsers;
	}

	static class User {
		static String ID;
		static String username;
		static String password;
		static String email;
		static String hwid;
		static String ip;
		static String expiry;
		static String lastLogin;
		static String registerDate;
	}

	public class OnProgramStart {
		public static String Name = null;

		public static void Initialize(String name, String secret, String version) {
			Name = name;
			try {
				Security.start();
				JSONObject json = new JSONObject();
				json.put("name", name);
				json.put("secret", secret);
				json.put("version", version);
				String jsonStr = json.toString();

				URL url = new URL(Constants.apiUrl + "applications/initialize");
				HttpURLConnection con = (HttpURLConnection) url.openConnection();
				con.setRequestMethod("POST");
				con.setRequestProperty("Content-Type", "application/json");
				con.setRequestProperty("Content-Length", String.valueOf(jsonStr.length()));
				con.setDoOutput(true);

				OutputStream os = con.getOutputStream();
				os.write(jsonStr.getBytes());
				os.flush();
				os.close();

				if (Security.maliciousCheck(Constants.timeSent)) {
					JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
							JOptionPane.WARNING_MESSAGE);
					System.exit(0);
				}
				if (Constants.breached) {
					JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
							JOptionPane.WARNING_MESSAGE);
					System.exit(0);
				}

				int responseCode = con.getResponseCode();
				if (responseCode == HttpURLConnection.HTTP_OK) {

					InputStream is = con.getInputStream();
					BufferedReader br = new BufferedReader(new InputStreamReader(is));
					StringBuilder response = new StringBuilder();
					String line;
					while ((line = br.readLine()) != null) {
						response.append(line);
					}
					br.close();
					is.close();

					JSONObject responseJson = new JSONObject(response.toString());
					Constants.initialized = true;
					ApplicationSettings.id = responseJson.getString("id");
					int statusInt = responseJson.optInt("status", -1);
					boolean status = (statusInt == 1);
					ApplicationSettings.status = status;
					int hwidCheckInt = responseJson.optInt("hwidCheck", -1);
					boolean hwidCheck = (hwidCheckInt == 1);
					ApplicationSettings.hwidCheck = hwidCheck;
					ApplicationSettings.programHash = responseJson.getString("programHash");
					ApplicationSettings.version = responseJson.getString("version");
					ApplicationSettings.downloadLink = responseJson.optString("downloadLink");
					int developerModeInt = responseJson.optInt("developerMode", -1);
					boolean developerMode = (developerModeInt == 1);
					ApplicationSettings.developerMode = developerMode;
					int freeModeInt = responseJson.optInt("freeMode", -1);
					boolean freeMode = (freeModeInt == 1);
					ApplicationSettings.freeMode = freeMode;

					if (ApplicationSettings.freeMode)
						JOptionPane.showMessageDialog(null, "Application is in Free Mode!", OnProgramStart.Name,
								JOptionPane.INFORMATION_MESSAGE);

					if (ApplicationSettings.developerMode) {
						JOptionPane.showMessageDialog(null,
								"Application is in Developer Mode, bypassing integrity and update check!",
								OnProgramStart.Name, JOptionPane.WARNING_MESSAGE);
						File file = new File(System.getProperty("user.dir") + "/integrity.log");
						file.createNewFile();
						String classpath = System.getProperty("java.class.path");
						String executablePath = new File(classpath).getAbsolutePath();
						String hash = Security.integrity(executablePath);
						try {
							FileWriter writer = new FileWriter("./integrity.log");
							writer.write(hash);
							writer.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
						JOptionPane.showMessageDialog(null,
								"Your applications hash has been saved to integrity.log, please refer to this when your application is ready for release!",
								OnProgramStart.Name, JOptionPane.INFORMATION_MESSAGE);
					} else {
						if (!ApplicationSettings.version.equals(version)) {
							JOptionPane.showMessageDialog(null,
									"Update " + ApplicationSettings.version + " available, redirecting to update!",
									OnProgramStart.Name, JOptionPane.ERROR_MESSAGE);
							try {
								Desktop.getDesktop().browse(new URI(ApplicationSettings.downloadLink));
							} catch (Exception e1) {
								e1.printStackTrace();
							}
							System.exit(0);
						}
						int integrityCheckInt = responseJson.optInt("integrityCheck", -1);
						boolean integrityCheck = (integrityCheckInt == 1);
						if (integrityCheck) {
							String classpath = System.getProperty("java.class.path");
							String executablePath = new File(classpath).getAbsolutePath();
							if (!ApplicationSettings.programHash.equals(Security.integrity(executablePath))) {
								JOptionPane.showMessageDialog(null,
										"File has been tampered with, couldn't verify integrity!", "Error",
										JOptionPane.ERROR_MESSAGE);
								System.exit(1);
							}
						}
					}
					if (!ApplicationSettings.status) {
						JOptionPane.showMessageDialog(null,
								"Looks like this application is disabled, please try again later!", "Error",
								JOptionPane.ERROR_MESSAGE);
						System.exit(0);
					}

				} else {
					InputStream is = con.getErrorStream();
					if (is != null) {
						BufferedReader br = new BufferedReader(new InputStreamReader(is));
						StringBuilder response = new StringBuilder();
						String line;
						while ((line = br.readLine()) != null) {
							response.append(line);
						}
						br.close();
						is.close();
						JSONObject responseJson = new JSONObject(response.toString());
						if (responseJson.getString("code").equals("UNAUTHORIZED")) {
							JOptionPane.showMessageDialog(null, responseJson.getString("message"), Name,
									JOptionPane.ERROR_MESSAGE);
							System.exit(0);
						} else if (responseJson.getString("code").equals("NOT_FOUND")) {
							JOptionPane.showMessageDialog(null, responseJson.getString("message"), Name,
									JOptionPane.ERROR_MESSAGE);
							System.exit(0);

						} else if (responseJson.getString("code").equals("VALIDATION_FAILED")) {
							JOptionPane.showMessageDialog(null,
									("Failed to initialize your application correctly in Main.java!\n\nDetials:\n"
											+ responseJson.getJSONObject("details").toString()),
									Name, JOptionPane.ERROR_MESSAGE);
							System.exit(0);

						}
					}
				}
				con.disconnect();
				Security.end();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static boolean login(String username, String password) {
		if (!Constants.initialized) {
			JOptionPane.showMessageDialog(null, "Please initialize your application first!", OnProgramStart.Name,
					JOptionPane.ERROR_MESSAGE);
			return false;
		}
		try {
			Security.start();
			Constants.timeSent = LocalDateTime.now();

			JSONObject json = new JSONObject();
			json.put("username", username);
			json.put("password", password);
			json.put("hwid", Constants.HWID());
			json.put("lastIP", Constants.IP());
			String jsonStr = json.toString();

			URL url = new URL(Constants.apiUrl + "users/login");
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("Content-Length", String.valueOf(jsonStr.length()));
			con.setDoOutput(true);

			OutputStream os = con.getOutputStream();
			os.write(jsonStr.getBytes());
			os.flush();
			os.close();

			if (Security.maliciousCheck(Constants.timeSent)) {
				JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}
			if (Constants.breached) {
				JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}

			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
				InputStream is = con.getInputStream();
				BufferedReader br = new BufferedReader(new InputStreamReader(is));
				StringBuilder response = new StringBuilder();
				String line;
				while ((line = br.readLine()) != null) {
					response.append(line);
				}
				br.close();
				is.close();

				JSONObject responseJson = new JSONObject(response.toString());

				User.ID = responseJson.getString("id");
				User.username = responseJson.getString("username");
				User.password = responseJson.getString("password");
				User.email = responseJson.getString("email");
				User.expiry = responseJson.getString("expiryDate");
				User.lastLogin = responseJson.getString("lastLogin");
				User.ip = responseJson.getString("lastIP");
				User.hwid = responseJson.getString("hwid");
				Security.end();
				return true;
			} else {
				InputStream is = con.getErrorStream();
				if (is != null) {
					BufferedReader br = new BufferedReader(new InputStreamReader(is));
					StringBuilder response = new StringBuilder();
					String line;
					while ((line = br.readLine()) != null) {
						response.append(line);
					}
					br.close();
					is.close();

					JSONObject responseJson = new JSONObject(response.toString());
					if (responseJson.getString("code").equals("UNAUTHORIZED")) {
						JOptionPane.showMessageDialog(null, responseJson.getString("message"), OnProgramStart.Name,
								JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("NOT_FOUND")) {
						JOptionPane.showMessageDialog(null, responseJson.getString("message"), OnProgramStart.Name,
								JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("VALIDATION_FAILED")) {
						JOptionPane.showMessageDialog(null, (responseJson.getJSONObject("details").toString()),
								OnProgramStart.Name, JOptionPane.ERROR_MESSAGE);
					}
				}
			}
			con.disconnect();
			Security.end();
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static boolean register(String username, String password, String email, String license) {
		if (!Constants.initialized) {
			JOptionPane.showMessageDialog(null, "Please initialize your application first!", OnProgramStart.Name,
					JOptionPane.ERROR_MESSAGE);
			return false;
		}
		try {
			Security.start();
			Constants.timeSent = LocalDateTime.now();

			JSONObject json = new JSONObject();
			json.put("username", username);
			json.put("password", password);
			json.put("email", email);
			json.put("license", license);
			json.put("hwid", Constants.HWID());
			json.put("lastIP", Constants.IP());
			json.put("id", ApplicationSettings.id);
			String jsonStr = json.toString();

			URL url = new URL(Constants.apiUrl + "users/register");
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("Content-Length", String.valueOf(jsonStr.length()));
			con.setDoOutput(true);

			OutputStream os = con.getOutputStream();
			os.write(jsonStr.getBytes());
			os.flush();
			os.close();

			if (Security.maliciousCheck(Constants.timeSent)) {
				JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}
			if (Constants.breached) {
				JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}

			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
				InputStream is = con.getInputStream();
				BufferedReader br = new BufferedReader(new InputStreamReader(is));
				StringBuilder response = new StringBuilder();
				String line;
				while ((line = br.readLine()) != null) {
					response.append(line);
				}
				br.close();
				is.close();

				JSONObject responseJson = new JSONObject(response.toString());

				User.ID = responseJson.getString("id");
				User.username = responseJson.getString("username");
				User.email = responseJson.getString("email");
				User.expiry = responseJson.getString("expiryDate");
				User.lastLogin = responseJson.getString("lastLogin");
				User.ip = responseJson.getString("lastIP");
				User.hwid = responseJson.getString("hwid");
				Security.end();
				return true;
			} else {
				InputStream is = con.getErrorStream();
				if (is != null) {
					BufferedReader br = new BufferedReader(new InputStreamReader(is));
					StringBuilder response = new StringBuilder();
					String line;
					while ((line = br.readLine()) != null) {
						response.append(line);
					}
					br.close();
					is.close();

					JSONObject responseJson = new JSONObject(response.toString());
					if (responseJson.getString("code").equals("NOT_FOUND")) {
						JOptionPane.showMessageDialog(null, responseJson.getString("message"), OnProgramStart.Name,
								JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("ER_DUP_ENTRY")) {
						JOptionPane.showMessageDialog(null, "User with this username already exists!",
								OnProgramStart.Name, JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("FORBIDDEN")) {
						JOptionPane.showMessageDialog(null, "User with this username already exists!",
								OnProgramStart.Name, JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("VALIDATION_FAILED")) {
						JOptionPane.showMessageDialog(null, (responseJson.getJSONObject("details").toString()),
								OnProgramStart.Name, JOptionPane.ERROR_MESSAGE);
					}
				}
			}
			con.disconnect();
			Security.end();
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static boolean extendSub(String username, String password, String license) {
		if (!Constants.initialized) {
			JOptionPane.showMessageDialog(null, "Please initialize your application first!", OnProgramStart.Name,
					JOptionPane.ERROR_MESSAGE);
			return false;
		}
		try {
			Security.start();
			Constants.timeSent = LocalDateTime.now();

			JSONObject json = new JSONObject();
			json.put("username", username);
			json.put("password", password);
			json.put("license", license);
			json.put("hwid", Constants.HWID());
			String jsonStr = json.toString();

			URL url = new URL(Constants.apiUrl + "users/upgrade");
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("PUT");
			con.setRequestProperty("Content-Type", "application/json");
			con.setRequestProperty("Content-Length", String.valueOf(jsonStr.length()));
			con.setDoOutput(true);

			OutputStream os = con.getOutputStream();
			os.write(jsonStr.getBytes());
			os.flush();
			os.close();

			if (Security.maliciousCheck(Constants.timeSent)) {
				JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}
			if (Constants.breached) {
				JOptionPane.showMessageDialog(null, "Possible malicious activity detected!", OnProgramStart.Name,
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}

			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
				InputStream is = con.getInputStream();
				BufferedReader br = new BufferedReader(new InputStreamReader(is));
				StringBuilder response = new StringBuilder();
				String line;
				while ((line = br.readLine()) != null) {
					response.append(line);
				}
				br.close();
				is.close();

				JSONObject responseJson = new JSONObject(response.toString());

				User.ID = responseJson.getString("id");
				User.username = responseJson.getString("username");
				User.email = responseJson.getString("email");
				User.expiry = responseJson.getString("expiryDate");
				User.lastLogin = responseJson.getString("lastLogin");
				User.ip = responseJson.getString("lastIP");
				User.hwid = responseJson.getString("hwid");
				Security.end();
				return true;
			} else {
				InputStream is = con.getErrorStream();
				if (is != null) {
					BufferedReader br = new BufferedReader(new InputStreamReader(is));
					StringBuilder response = new StringBuilder();
					String line;
					while ((line = br.readLine()) != null) {
						response.append(line);
					}
					br.close();
					is.close();

					JSONObject responseJson = new JSONObject(response.toString());
					if (responseJson.getString("code").equals("NOT_FOUND")) {
						JOptionPane.showMessageDialog(null, responseJson.getString("message"), OnProgramStart.Name,
								JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("UNAUTHORIZED")) {
						JOptionPane.showMessageDialog(null, responseJson.getString("message"), OnProgramStart.Name,
								JOptionPane.ERROR_MESSAGE);
					} else if (responseJson.getString("code").equals("VALIDATION_FAILED")) {
						JOptionPane.showMessageDialog(null, (responseJson.getJSONObject("details").toString()),
								OnProgramStart.Name, JOptionPane.ERROR_MESSAGE);
					}
				}
			}
			con.disconnect();
			Security.end();
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public class Security {
		public static void start() {
			String drive = Paths.get(System.getenv("SystemRoot")).getRoot().toString();
			if (Constants.started) {
				JOptionPane.showMessageDialog(null, "A session has already been started, please end the previous one!",
						OnProgramStart.Name, JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			} else {
				try (BufferedReader br = new BufferedReader(new InputStreamReader(
						new FileInputStream(drive + "\\Windows\\System32\\drivers\\etc\\hosts")))) {
					StringBuilder sb = new StringBuilder();
					String line;
					while ((line = br.readLine()) != null) {
						sb.append(line).append("\n");
					}
					String contents = sb.toString();
					if (contents.contains("api.blitzware.xyz")) {
						Constants.breached = true;
						JOptionPane.showMessageDialog(null, "DNS redirecting has been detected!", OnProgramStart.Name,
								JOptionPane.ERROR_MESSAGE);
						System.exit(0);
					}
				} catch (IOException e) {
					// Handle the exception
				}
				Constants.started = true;
			}
		}

		public static void end() {
			if (!Constants.started) {
				JOptionPane.showMessageDialog(null, "No session has been started, closing for security reasons!",
						OnProgramStart.Name, JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			} else {
				Constants.started = false;
			}
		}

		public static String integrity(String filename) {
			String result = "";
			try (FileInputStream fis = new FileInputStream(filename)) {
				MessageDigest md = MessageDigest.getInstance("MD5");
				byte[] dataBytes = new byte[1024];
				int nread = 0;
				while ((nread = fis.read(dataBytes)) != -1) {
					md.update(dataBytes, 0, nread);
				}
				byte[] mdbytes = md.digest();
				StringBuilder sb = new StringBuilder();
				for (byte b : mdbytes) {
					sb.append(String.format("%02x", b));
				}
				result = sb.toString();
			} catch (IOException | NoSuchAlgorithmException e) {
				// Handle the exception
				System.out.println(e.getMessage());
			}
			return result;
		}

		public static boolean maliciousCheck(LocalDateTime date) {
			LocalDateTime dt1 = date; // time sent
			LocalDateTime dt2 = LocalDateTime.now(); // time received
			Duration d3 = Duration.between(dt1, dt2);
			if (Math.abs(d3.getSeconds()) >= 5 || Math.abs(d3.toMinutes()) >= 1) {
				Constants.breached = true;
				return true;
			} else {
				return false;
			}
		}
	}
}
