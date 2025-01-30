import tkinter as tk
from tkinter import filedialog, messagebox
import csv
from collections import defaultdict
from datetime import datetime, timedelta
import os


# This function reads the log file and keeps track of failed and successful login attempts
def read_log_file(file_path):
    failed_logins = []
    successful_logins = []

    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            try:
                log_time = datetime.strptime(row['Time'], '%d/%m/%Y %H:%M')
                status_code = row['Status Code']
                ip = row['IP']

                if status_code in ('200', '201'):
                    successful_logins.append({'ip': ip, 'time': log_time})
                else:
                    failed_logins.append({'ip': ip, 'time': log_time})
            except ValueError as e:
                print(f"Skipping line due to invalid date format: {row['Time']} -> {e}")

    return failed_logins, successful_logins


# This function organizes the failed login attempts by IP address
def track_failed_attempts(failed_logins):
    failed_attempts = defaultdict(list)
    for log in failed_logins:
        failed_attempts[log['ip']].append(log['time'])
    return failed_attempts


# This function detects brute force attacks based on login attempts in a short time frame
def detect_brute_force(failed_attempts):
    brute_force_ips = {}

    for ip, attempts in failed_attempts.items():
        attempts.sort()
        for i in range(len(attempts) - 2):
            window = [attempts[j] for j in range(i, i + 3)]
            if (window[-1] - window[0]).total_seconds() <= 300:
                brute_force_ips[ip] = {'start': window[0], 'end': window[-1]}
                break

    return brute_force_ips


# This function checks if a successful login occurred after the brute-force window
def check_successful_logins(successful_logins, brute_force_ips):
    success_dict = {ip: "No" for ip in brute_force_ips}

    for success in successful_logins:
        ip = success['ip']
        success_time = success['time']

        if ip in brute_force_ips and success_time >= brute_force_ips[ip]['end']:
            success_dict[ip] = "Yes"

    return success_dict


# This function generates a CSV report
def generate_report(failed_attempts, brute_force_ips, success_dict):
    with open('suspicious_activity.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Start', 'End', 'Attempts', 'Success: Yes/No']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip, details in brute_force_ips.items():
            writer.writerow({
                'IP': ip,
                'Start': details['start'].strftime('%d/%m/%Y %H:%M'),
                'End': details['end'].strftime('%d/%m/%Y %H:%M'),
                'Attempts': len(failed_attempts[ip]),
                'Success: Yes/No': success_dict[ip]
            })

    if brute_force_ips:
        messagebox.showwarning("Brute Force Attack Detected",
                               "Warning: Potential Brute Force Attack detected! A report has been generated.")
    else:
        messagebox.showinfo("No Brute Force Detected", "No brute force attacks detected.")


# This function is triggered when the user selects a file
def start_process():
    file_path = filedialog.askopenfilename(title="Select Log File", filetypes=[("CSV Files", "*.csv")])

    if not file_path:
        messagebox.showwarning("File Not Selected", "Please select a valid CSV file.")
        return

    try:
        failed_logins, successful_logins = read_log_file(file_path)
        failed_attempts = track_failed_attempts(failed_logins)
        brute_force_ips = detect_brute_force(failed_attempts)
        success_dict = check_successful_logins(successful_logins, brute_force_ips)
        generate_report(failed_attempts, brute_force_ips, success_dict)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


# Set up the Tkinter GUI
root = tk.Tk()
root.title("Brute Force Detection Tool")
root.geometry("400x200")

label = tk.Label(root, text="Select a log file to analyze for brute force attacks.", padx=10, pady=10)
label.pack()

process_button = tk.Button(root, text="Process Log File", command=start_process, padx=20, pady=10)
process_button.pack()

root.mainloop()
