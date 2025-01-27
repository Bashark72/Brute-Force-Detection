Brute Force Detection Tool
This project is a Brute Force Detection Tool designed to identify and prevent brute force attacks on systems or applications. It analyzes login attempts, detects suspicious patterns, and helps improve security by flagging potential intrusions.

Features:
1)CSV File Input: Input a CSV file with login attempt data.
2)Suspicious Activity Detection: Filters out login attempts that exhibit suspicious patterns (e.g., multiple failed attempts from the same IP address).
3)CSV Output: Generates a new CSV file containing only the suspicious login attempts for further review.
4)Customizable Thresholds: Set the maximum number of failed login attempts and the time window to detect brute force attacks.
***Usage***
Prepare your CSV file with login attempt data. The file should have the following columns (adjust to your needs):

1)timestamp: The timestamp of the login attempt.
2)ip_address: The IP address of the user attempting to log in.
3)status: The result of the login attempt (e.g., "failed", "success").
The tool will analyze the login attempts, detect suspicious activity, and create a new CSV file, e.g., suspicious_activity.csv, containing only the flagged attempts.
****Contributing****
Contributions are welcome! Feel free to fork this repository, open issues, or submit pull requests. For major changes, please open an issue first to discuss what you would like to change.
