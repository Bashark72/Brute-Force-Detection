import tkinter as tk
from tkinter import filedialog, messagebox
import csv
from collections import defaultdict
from datetime import datetime, timedelta
import os


# This function reads the log file and keeps track of failed login attempts
def read_log_file(file_path):
    failed_logins = []
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            try:
                # Try to convert the time format and store the failed login attempt details
                failed_logins.append({
                    'ip': row['IP'],
                    'time': datetime.strptime(row['Time'], '%d/%m/%Y %H:%M'),
                    # This matches your log format (DD/MM/YYYY HH:MM)
                    'request': row['Request'],
                    'status code': row['Status Code'],
                })
            except ValueError as e:
                # If the date format doesn't match, we'll skip that row and print a message
                print(f"Skipping line due to invalid date format: {row['Time']} -> {e}")
    return failed_logins


# This function organizes the failed login attempts by IP address
def track_failed_attempts(failed_logins):
    failed_attempt = defaultdict(list)
    for log in failed_logins:
        ip = log['ip']
        failed_attempt[ip].append(log['time'])  # For each IP, we append the time of the failed login
    return failed_attempt


# This function looks for patterns that could indicate a brute force attack (multiple attempts in a short time frame)
def detect_brute_force(failed_attempts):
    brute_force_ips = set()
    for ip, attempts in failed_attempts.items():
        attempts.sort()  # We sort the login attempts for this IP by time
        # We check if there are 3 or more failed logins within 5 minutes
        for i in range(len(attempts) - 2):
            window = [attempts[j] for j in range(i, i + 3)]
            if (window[-1] - window[0]).total_seconds() <= 300:  # If the time difference is 5 minutes or less
                brute_force_ips.add(ip)  # This IP is a potential brute force attacker
                break
    return brute_force_ips


# This function generates a CSV report of any detected brute force activity
def generate_report(failed_attempts, brute_force_ips):
    # We'll save the results into a CSV file
    with open('suspicious_activity.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Start', 'End', 'Attempts']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()  # Write the column headers

        # Go through each failed attempt and add it to the report if it's related to brute force
        for ip, attempts in failed_attempts.items():
            if ip in brute_force_ips:
                attempts.sort()  # Sort the attempts by time
                writer.writerow({
                    'IP': ip,
                    'Start': attempts[0].strftime('%d/%m/%Y %H:%M'),  # Start time of brute force attempts
                    'End': attempts[-1].strftime('%d/%m/%Y %H:%M'),  # End time of brute force attempts
                    'Attempts': len(attempts),  # Number of failed attempts
                })

    # Show a warning if brute force was detected, or let the user know if no attack was found
    if brute_force_ips:
        messagebox.showwarning("Brute Force Attack Detected",
                               "Warning: Potential Brute Force Attack detected! A report has been generated.")
    else:
        messagebox.showinfo("No Brute Force Detected", "No brute force attacks detected.")


# This function is the heart of the UI interaction
def start_process():
    # Ask the user to select a CSV file using a file dialog
    file_path = filedialog.askopenfilename(title="Select Log File", filetypes=[("CSV Files", "*.csv")])

    if not file_path:
        # If no file is selected, show a warning
        messagebox.showwarning("File Not Selected", "Please select a valid CSV file.")
        return

    # Try to process the selected file
    try:
        # Read the log file, track failed login attempts, detect brute force, and generate the report
        failed_logins = read_log_file(file_path)
        failed_attempts = track_failed_attempts(failed_logins)
        brute_force_ips = detect_brute_force(failed_attempts)
        generate_report(failed_attempts, brute_force_ips)
    except Exception as e:
        # If something goes wrong, show an error message
        messagebox.showerror("Error", f"An error occurred: {e}")


# Set up the main window for the app using Tkinter
root = tk.Tk()
root.title("Brute Force Detection Tool")  # Give the window a title
root.geometry("400x200")  # Set the size of the window

# Create and display the label on the window
label = tk.Label(root, text="Select a log file to analyze for brute force attacks.", padx=10, pady=10)
label.pack()

# Create and display the button that starts the process when clicked
process_button = tk.Button(root, text="Process Log File", command=start_process, padx=20, pady=10)
process_button.pack()

# Start the Tkinter event loop to run the app
root.mainloop()
