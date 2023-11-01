#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog
import requests
import pyfiglet
import time
import webbrowser

def print_header():
    ascii_banner = pyfiglet.figlet_format("VirusTotal Automation")
    print(ascii_banner)
    name_banner = pyfiglet.figlet_format("by Itay Yogev", font="mini")
    print(name_banner)
    time.sleep(2)

def get_malware_path():
    print("\nChoose the malware:\n")
    time.sleep(2)
    root = tk.Tk()
    root.withdraw()
    filename = filedialog.askopenfilename()
    root.destroy()
    return filename

def scan_file(malware_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (malware_path, open(malware_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    response_json = response.json()
    resource = response_json.get('resource')
    return resource

def get_file_report(resource_id, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource_id}
    response = requests.get(url, params=params)
    file_report_output = response.json()
    total = file_report_output.get('total')
    positives = file_report_output.get('positives')
    print(f"Resources: {total}")
    print(f"Positives: {positives}\n")

    while True:
        choice = input("Choose your action:\n* For hashes press H\n* For Common names press N\n* For GUI Virustotal press G:\n\nEnter Your Choice: ")
        if choice.lower() == 'h':
            sha1 = file_report_output.get('sha1')
            print(f"\nsha1: {sha1}")
            sha256 = file_report_output.get('sha1')
            print(f"sha256: {sha256}")
            md5 = file_report_output.get('md5')
            print(f"md5: {md5}\n")
        elif choice.lower() == 'n':
            results_dict = {}

            for resource, scan_data in file_report_output['scans'].items():
                if scan_data.get('result') is not None:
                    results_dict[resource] = scan_data['result']

            print("\n")
            for resource, result in results_dict.items():
                print(result)
            print("\n")
        elif choice.lower() == 'g':
            link = file_report_output.get('permalink')
            webbrowser.open(link)
            print()
        else:
            print("\nWrong action. Please try again.\n")

if __name__ == '__main__':
    print_header()
    malware_path = get_malware_path()
    api_key = '<apikey>'
    resource_output = scan_file(malware_path, api_key)
    get_file_report(resource_output, api_key)
