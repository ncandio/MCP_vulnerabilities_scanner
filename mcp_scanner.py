import os
import json
import time
import hashlib
import threading
import configparser
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
from zapv2 import ZAPv2

class SecurityScannerMCP:
    """Main application class for the Security Scanner MCP application."""
    
    def __init__(self, root):
        """Initialize the application UI and load configuration.
        
        Args:
            root: The tkinter root window
        """
        self.root = root
        self.root.title("Security Scanner MCP")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        
        # API keys and configuration
        self.config = configparser.ConfigParser()
        self.load_configuration()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_file_scan_tab()
        self.setup_web_scan_tab()
        self.setup_config_tab()
        self.setup_results_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initialize scanners
        self.scanners = {
            "VirusTotal": VirusTotalScanner(self.config.get('API_KEYS', 'virustotal', fallback='')),
            "OWASP ZAP": OWASPZAPScanner(self.config.get('API_KEYS', 'owasp_zap', fallback='')),
            "Dependency Check": DependencyScanner(self.config.get('API_KEYS', 'dependency_check', fallback=''))
        }
        
    def load_configuration(self):
        """Load application configuration from config.ini or create default if not exists."""
        if os.path.exists('config.ini'):
            self.config.read('config.ini')
        else:
            # Create default configuration
            self.config['API_KEYS'] = {
                'virustotal': '',
                'owasp_zap': '',
                'dependency_check': ''
            }
            self.config['SETTINGS'] = {
                'save_reports': 'yes',
                'report_directory': './reports'
            }
            self.save_configuration()
    
    def save_configuration(self):
        """Save current configuration to config.ini file."""
        with open('config.ini', 'w', encoding='utf-8') as configfile:
            self.config.write(configfile)
    
    def setup_dashboard_tab(self):
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Title
        title_label = tk.Label(dashboard_frame, text="Security Scanner MCP Dashboard", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=20)
        
        # Scanner status frame
        status_frame = ttk.LabelFrame(dashboard_frame, text="Connected Scanners")
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Scanner status indicators
        scanners = ["VirusTotal", "OWASP ZAP", "Dependency Scanner"]
        for i, scanner in enumerate(scanners):
            scanner_frame = ttk.Frame(status_frame)
            scanner_frame.pack(fill=tk.X, padx=5, pady=5)
            
            scanner_label = ttk.Label(scanner_frame, text=scanner, width=20)
            scanner_label.pack(side=tk.LEFT, padx=5)
            
            status_label = ttk.Label(scanner_frame, text="Not Configured" if i > 0 else "Connected", 
                                    foreground="red" if i > 0 else "green")
            status_label.pack(side=tk.LEFT, padx=5)
        
        # Recent scans frame
        recent_frame = ttk.LabelFrame(dashboard_frame, text="Recent Scans")
        recent_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Sample scan data
        scan_data = [
            {"date": "2025-05-19 09:15", "type": "File Scan", "target": "application.exe", "findings": "3 High, 2 Medium"},
            {"date": "2025-05-18 14:22", "type": "Web Scan", "target": "https://example.com", "findings": "1 High, 5 Medium"},
        ]
        
        # Create treeview
        columns = ("Date", "Type", "Target", "Findings")
        tree = ttk.Treeview(recent_frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        # Add data
        for i, item in enumerate(scan_data):
            tree.insert("", tk.END, values=(item["date"], item["type"], item["target"], item["findings"]))
        
        tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Quick scan button
        scan_button = ttk.Button(dashboard_frame, text="Start New Scan", command=lambda: self.notebook.select(1))
        scan_button.pack(pady=20)
        
    def setup_file_scan_tab(self):
        file_frame = ttk.Frame(self.notebook)
        self.notebook.add(file_frame, text="File Scan")
        
        # File selection
        file_select_frame = ttk.LabelFrame(file_frame, text="Select File")
        file_select_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=60)
        file_entry.pack(side=tk.LEFT, padx=5, pady=10, expand=True, fill=tk.X)
        
        browse_button = ttk.Button(file_select_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT, padx=5, pady=10)
        
        # Scanner selection
        scanner_frame = ttk.LabelFrame(file_frame, text="Select Scanners")
        scanner_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Checkbuttons for scanners
        self.virustotal_var = tk.BooleanVar(value=True)
        virustotal_check = ttk.Checkbutton(scanner_frame, text="VirusTotal", variable=self.virustotal_var)
        virustotal_check.pack(anchor=tk.W, padx=5, pady=5)
        
        self.dependency_var = tk.BooleanVar()
        dependency_check = ttk.Checkbutton(scanner_frame, text="Dependency Scanner", variable=self.dependency_var)
        dependency_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Scan button
        scan_button = ttk.Button(file_frame, text="Start File Scan", command=self.start_file_scan)
        scan_button.pack(pady=20)
        
        # Progress
        self.file_progress_var = tk.DoubleVar()
        progress = ttk.Progressbar(file_frame, variable=self.file_progress_var, maximum=100)
        progress.pack(fill=tk.X, padx=20, pady=10)
        
        # Results area
        results_frame = ttk.LabelFrame(file_frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.file_results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.file_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_web_scan_tab(self):
        web_frame = ttk.Frame(self.notebook)
        self.notebook.add(web_frame, text="Web Scan")
        
        # URL input
        url_frame = ttk.LabelFrame(web_frame, text="Enter URL")
        url_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=60)
        url_entry.pack(padx=5, pady=10, fill=tk.X)
        
        # Scanner selection
        scanner_frame = ttk.LabelFrame(web_frame, text="Select Scanners")
        scanner_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Checkbuttons for scanners
        self.zap_var = tk.BooleanVar(value=True)
        zap_check = ttk.Checkbutton(scanner_frame, text="OWASP ZAP", variable=self.zap_var)
        zap_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(web_frame, text="Scan Options")
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.crawl_var = tk.BooleanVar(value=True)
        crawl_check = ttk.Checkbutton(options_frame, text="Crawl Website", variable=self.crawl_var)
        crawl_check.pack(anchor=tk.W, padx=5, pady=5)
        
        self.ajax_var = tk.BooleanVar()
        ajax_check = ttk.Checkbutton(options_frame, text="AJAX Spider", variable=self.ajax_var)
        ajax_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Scan button
        scan_button = ttk.Button(web_frame, text="Start Web Scan", command=self.start_web_scan)
        scan_button.pack(pady=20)
        
        # Progress
        self.web_progress_var = tk.DoubleVar()
        progress = ttk.Progressbar(web_frame, variable=self.web_progress_var, maximum=100)
        progress.pack(fill=tk.X, padx=20, pady=10)
        
        # Results area
        results_frame = ttk.LabelFrame(web_frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.web_results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.web_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_config_tab(self):
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # API Keys
        api_frame = ttk.LabelFrame(config_frame, text="API Keys")
        api_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # VirusTotal API Key
        vt_frame = ttk.Frame(api_frame)
        vt_frame.pack(fill=tk.X, padx=5, pady=5)
        
        vt_label = ttk.Label(vt_frame, text="VirusTotal API Key:", width=20)
        vt_label.pack(side=tk.LEFT, padx=5)
        
        self.vt_api_var = tk.StringVar(value=self.config.get('API_KEYS', 'virustotal', fallback=''))
        vt_entry = ttk.Entry(vt_frame, textvariable=self.vt_api_var, width=50)
        vt_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # OWASP ZAP API Key
        zap_frame = ttk.Frame(api_frame)
        zap_frame.pack(fill=tk.X, padx=5, pady=5)
        
        zap_label = ttk.Label(zap_frame, text="OWASP ZAP API Key:", width=20)
        zap_label.pack(side=tk.LEFT, padx=5)
        
        self.zap_api_var = tk.StringVar(value=self.config.get('API_KEYS', 'owasp_zap', fallback=''))
        zap_entry = ttk.Entry(zap_frame, textvariable=self.zap_api_var, width=50)
        zap_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Dependency Scanner API Key
        dep_frame = ttk.Frame(api_frame)
        dep_frame.pack(fill=tk.X, padx=5, pady=5)
        
        dep_label = ttk.Label(dep_frame, text="Dependency Scanner:", width=20)
        dep_label.pack(side=tk.LEFT, padx=5)
        
        self.dep_api_var = tk.StringVar(value=self.config.get('API_KEYS', 'dependency_check', fallback=''))
        dep_entry = ttk.Entry(dep_frame, textvariable=self.dep_api_var, width=50)
        dep_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Settings
        settings_frame = ttk.LabelFrame(config_frame, text="Settings")
        settings_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Save Reports
        save_reports_frame = ttk.Frame(settings_frame)
        save_reports_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.save_reports_var = tk.BooleanVar(value=self.config.get('SETTINGS', 'save_reports', fallback='yes') == 'yes')
        save_reports_check = ttk.Checkbutton(save_reports_frame, text="Save Reports", variable=self.save_reports_var)
        save_reports_check.pack(anchor=tk.W, padx=5)
        
        # Report Directory
        report_dir_frame = ttk.Frame(settings_frame)
        report_dir_frame.pack(fill=tk.X, padx=5, pady=5)
        
        report_dir_label = ttk.Label(report_dir_frame, text="Report Directory:", width=20)
        report_dir_label.pack(side=tk.LEFT, padx=5)
        
        self.report_dir_var = tk.StringVar(value=self.config.get('SETTINGS', 'report_directory', fallback='./reports'))
        report_dir_entry = ttk.Entry(report_dir_frame, textvariable=self.report_dir_var, width=50)
        report_dir_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        browse_dir_button = ttk.Button(report_dir_frame, text="Browse", command=self.browse_directory)
        browse_dir_button.pack(side=tk.RIGHT, padx=5)
        
        # Save button
        save_button = ttk.Button(config_frame, text="Save Configuration", command=self.save_config)
        save_button.pack(pady=20)
        
    def setup_results_tab(self):
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results History")
        
        # Search frame
        search_frame = ttk.Frame(results_frame)
        search_frame.pack(fill=tk.X, padx=20, pady=10)
        
        search_label = ttk.Label(search_frame, text="Search:")
        search_label.pack(side=tk.LEFT, padx=5)
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        search_button = ttk.Button(search_frame, text="Search", command=self.search_results)
        search_button.pack(side=tk.LEFT, padx=5)
        
        # Results table
        table_frame = ttk.Frame(results_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        columns = ("Date", "Type", "Target", "Findings", "Actions")
        self.results_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            if col == "Target":
                self.results_tree.column(col, width=200)
            elif col == "Actions":
                self.results_tree.column(col, width=100)
            else:
                self.results_tree.column(col, width=100)
        
        # Sample data
        results_data = [
            {"date": "2025-05-19 09:15", "type": "File Scan", "target": "application.exe", "findings": "3 High, 2 Medium"},
            {"date": "2025-05-18 14:22", "type": "Web Scan", "target": "https://example.com", "findings": "1 High, 5 Medium"},
            {"date": "2025-05-17 11:30", "type": "File Scan", "target": "library.dll", "findings": "0 High, 1 Medium"},
        ]
        
        # Add data
        for i, item in enumerate(results_data):
            self.results_tree.insert("", tk.END, values=(item["date"], item["type"], item["target"], item["findings"], "View"))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree.pack(fill=tk.BOTH, expand=True)
        self.results_tree.bind("<ButtonRelease-1>", self.on_result_click)
        
    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select file to scan")
        if filename:
            self.file_path_var.set(filename)
            
    def browse_directory(self):
        directory = filedialog.askdirectory(title="Select report directory")
        if directory:
            self.report_dir_var.set(directory)
            
    def save_config(self):
        # Update config with current values
        self.config['API_KEYS'] = {
            'virustotal': self.vt_api_var.get(),
            'owasp_zap': self.zap_api_var.get(),
            'dependency_check': self.dep_api_var.get()
        }
        
        self.config['SETTINGS'] = {
            'save_reports': 'yes' if self.save_reports_var.get() else 'no',
            'report_directory': self.report_dir_var.get()
        }
        
        # Save to file
        self.save_configuration()
        
        # Update scanners with new API keys
        for scanner_name, scanner in self.scanners.items():
            if scanner_name == "VirusTotal":
                scanner.set_api_key(self.vt_api_var.get())
            elif scanner_name == "OWASP ZAP":
                scanner.set_api_key(self.zap_api_var.get())
            elif scanner_name == "Dependency Check":
                scanner.set_api_key(self.dep_api_var.get())
        
        messagebox.showinfo("Configuration", "Configuration saved successfully!")
        
    def start_file_scan(self):
        file_path = self.file_path_var.get()
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file to scan")
            return
            
        # Clear previous results
        self.file_results_text.delete(1.0, tk.END)
        self.file_results_text.insert(tk.END, f"Starting scan of file: {file_path}\n\n")
        
        # Reset progress
        self.file_progress_var.set(0)
        
        # Get selected scanners
        selected_scanners = []
        if self.virustotal_var.get():
            selected_scanners.append("VirusTotal")
        if self.dependency_var.get():
            selected_scanners.append("Dependency Check")
            
        if not selected_scanners:
            messagebox.showerror("Error", "Please select at least one scanner")
            return
            
        # Start scan in a thread
        self.status_var.set(f"Scanning file: {os.path.basename(file_path)}...")
        threading.Thread(target=self.run_file_scan, args=(file_path, selected_scanners)).start()
        
    def run_file_scan(self, file_path, selected_scanners):
        """Execute file scan with selected scanners and process results.
        
        Args:
            file_path: Path to the file to scan
            selected_scanners: List of scanner names to use
        """
        try:
            total_scanners = len(selected_scanners)
            progress_increment = 100 / total_scanners
            current_progress = 0
            
            results = {}
            
            for scanner_name in selected_scanners:
                scanner = self.scanners.get(scanner_name)
                if scanner:
                    self.update_status(f"Running {scanner_name} scan...")
                    self.update_file_results(f"Running {scanner_name} scan...\n")
                    
                    try:
                        # Run the scan
                        scan_result = scanner.scan_file(file_path)
                        results[scanner_name] = scan_result
                        
                        # Update results text
                        self.update_file_results(f"{scanner_name} scan completed\n")
                        self.update_file_results(f"Results:\n{json.dumps(scan_result, indent=2)}\n\n")
                    except Exception as e:
                        self.update_file_results(f"Error in {scanner_name} scan: {str(e)}\n\n")
                        results[scanner_name] = {"error": str(e)}
                
                current_progress += progress_increment
                self.file_progress_var.set(current_progress)
                
            # Scan completed
            self.file_progress_var.set(100)
            self.update_status("File scan completed")
            self.update_file_results("Scan completed. Summary:\n")
            
            # Generate summary
            total_high = 0
            total_medium = 0
            total_low = 0
            
            for scanner_name, result in results.items():
                if "error" in result:
                    continue
                    
                if scanner_name == "VirusTotal":
                    detections = result.get("positives", 0)
                    if detections > 5:
                        total_high += 1
                    elif detections > 0:
                        total_medium += 1
                    
                if scanner_name == "Dependency Check":
                    vulnerabilities = result.get("vulnerabilities", [])
                    for vuln in vulnerabilities:
                        severity = vuln.get("severity", "").lower()
                        if severity == "high":
                            total_high += 1
                        elif severity == "medium":
                            total_medium += 1
                        elif severity == "low":
                            total_low += 1
            
            summary = f"Found {total_high} High, {total_medium} Medium, and {total_low} Low severity issues.\n"
            self.update_file_results(summary)
            
            # Save report if enabled
            if self.save_reports_var.get():
                report_dir = self.report_dir_var.get()
                if not os.path.exists(report_dir):
                    os.makedirs(report_dir)
                    
                report_file = os.path.join(report_dir, 
                                        f"file_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                with open(report_file, "w", encoding='utf-8') as f:
                    json.dump({
                        "file": file_path,
                        "scan_date": datetime.now().isoformat(),
                        "results": results,
                        "summary": {
                            "high": total_high,
                            "medium": total_medium,
                            "low": total_low
                        }
                    }, f, indent=2)
                    
                self.update_file_results(f"\nReport saved to: {report_file}\n")
            
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            self.update_file_results(f"Error: {str(e)}\n")
    
    def start_web_scan(self):
        url = self.url_var.get()
        
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scan")
            return
            
        # Validate URL format
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_var.set(url)
            
        # Clear previous results
        self.web_results_text.delete(1.0, tk.END)
        self.web_results_text.insert(tk.END, f"Starting scan of URL: {url}\n\n")
        
        # Reset progress
        self.web_progress_var.set(0)
        
        # Get selected scanners
        selected_scanners = []
        if self.zap_var.get():
            selected_scanners.append("OWASP ZAP")
            
        if not selected_scanners:
            messagebox.showerror("Error", "Please select at least one scanner")
            return
            
        # Get scan options
        options = {
            "crawl": self.crawl_var.get(),
            "ajax": self.ajax_var.get()
        }
            
        # Start scan in a thread
        self.status_var.set(f"Scanning URL: {url}...")
        threading.Thread(target=self.run_web_scan, args=(url, selected_scanners, options)).start()
    
    def run_web_scan(self, url, selected_scanners, options):
        try:
            total_scanners = len(selected_scanners)
            progress_increment = 100 / total_scanners
            current_progress = 0
            
            results = {}
            
            for scanner_name in selected_scanners:
                scanner = self.scanners.get(scanner_name)
                if scanner:
                    self.update_status(f"Running {scanner_name} scan...")
                    self.update_web_results(f"Running {scanner_name} scan...\n")
                    
                    try:
                        # Run the scan
                        scan_result = scanner.scan_url(url, options)
                        results[scanner_name] = scan_result
                        
                        # Update results text
                        self.update_web_results(f"{scanner_name} scan completed\n")
                        self.update_web_results(f"Results:\n{json.dumps(scan_result, indent=2)}\n\n")
                    except Exception as e:
                        self.update_web_results(f"Error in {scanner_name} scan: {str(e)}\n\n")
                        results[scanner_name] = {"error": str(e)}
                
                current_progress += progress_increment
                self.web_progress_var.set(current_progress)
                
            # Scan completed
            self.web_progress_var.set(100)
            self.update_status("Web scan completed")
            self.update_web_results("Scan completed. Summary:\n")
            
            # Generate summary
            total_high = 0
            total_medium = 0
            total_low = 0
            
            if "OWASP ZAP" in results:
                alerts = results["OWASP ZAP"].get("alerts", [])
                for alert in alerts:
                    risk = alert.get("risk", "").lower()
                    if risk == "high":
                        total_high += 1
                    elif risk == "medium":
                        total_medium += 1
                    elif risk == "low":
                        total_low += 1
            
            summary = f"Found {total_high} High, {total_medium} Medium, and {total_low} Low severity issues.\n"
            self.update_web_results(summary)
            
            # Save report if enabled
            if self.save_reports_var.get():
                report_dir = self.report_dir_var.get()
                if not os.path.exists(report_dir):
                    os.makedirs(report_dir)
                    
                report_file = os.path.join(report_dir, f"web_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                with open(report_file, "w") as f:
                    json.dump({
                        "url": url,
                        "scan_date": datetime.now().isoformat(),
                        "options": options,
                        "results": results,
                        "summary": {
                            "high": total_high,
                            "medium": total_medium,
                            "low": total_low
                        }
                    }, f, indent=2)
                    
                self.update_web_results(f"\nReport saved to: {report_file}\n")
            
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            self.update_web_results(f"Error: {str(e)}\n")
    
    def search_results(self):
        search_term = self.search_var.get().lower()
        
        # Clear tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Sample data (in a real app, this would come from saved reports)
        results_data = [
            {"date": "2025-05-19 09:15", "type": "File Scan", "target": "application.exe", "findings": "3 High, 2 Medium"},
            {"date": "2025-05-18 14:22", "type": "Web Scan", "target": "https://example.com", "findings": "1 High, 5 Medium"},
            {"date": "2025-05-17 11:30", "type": "File Scan", "target": "library.dll", "findings": "0 High, 1 Medium"},
        ]
        
        # Filter by search term
        filtered_data = []
        for item in results_data:
            for value in item.values():
                if search_term in str(value).lower():
                    filtered_data.append(item)
                    break
                    
        # Add filtered data
        for item in filtered_data:
            self.results_tree.insert("", tk.END, values=(item["date"], item["type"], item["target"], item["findings"], "View"))
    
    def on_result_click(self, event):
        region = self.results_tree.identify_region(event.x, event.y)
        if region == "cell":
            column = self.results_tree.identify_column(event.x)
            # Check if the Actions column (5th column) was clicked
            if column == "#5":  # Actions column
                item = self.results_tree.selection()[0]
                values = self.results_tree.item(item, "values")
                
                # Show result details
                self.show_result_details(values)
                
    def show_result_details(self, values):
        date, scan_type, target, findings = values[:4]
        
        # Create a details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Scan Details - {target}")
        details_window.geometry("800x600")
        
        # Header
        header_frame = ttk.Frame(details_window)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(header_frame, text=f"Scan Type: {scan_type}", font=("Helvetica", 12)).pack(anchor=tk.W)
        ttk.Label(header_frame, text=f"Target: {target}", font=("Helvetica", 12)).pack(anchor=tk.W)
        ttk.Label(header_frame, text=f"Date: {date}", font=("Helvetica", 12)).pack(anchor=tk.W)
        ttk.Label(header_frame, text=f"Findings: {findings}", font=("Helvetica", 12)).pack(anchor=tk.W)
        
        # Details
        details_frame = ttk.LabelFrame(details_window, text="Detailed Results")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
        details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # In a real app, we would load the actual report file here
        # For now, just show some sample data
        if scan_type == "File Scan":
            if "High" in findings:
                details_text.insert(tk.END, "=== HIGH SEVERITY ISSUES ===\n\n")
                details_text.insert(tk.END, "Issue: Malware Detected\n")
                details_text.insert(tk.END, "Details: The file contains code patterns matching known malware signatures.\n")
                details_text.insert(tk.END, "Recommendation: Remove or quarantine the file immediately.\n\n")
                
                details_text.insert(tk.END, "Issue: Insecure Crypto Implementation\n")
                details_text.insert(tk.END, "Details: The file uses outdated cryptographic algorithms (MD5, RC4).\n")
                details_text.insert(tk.END, "Recommendation: Update to secure algorithms like SHA-256 and AES.\n\n")
            
            if "Medium" in findings:
                details_text.insert(tk.END, "=== MEDIUM SEVERITY ISSUES ===\n\n")
                details_text.insert(tk.END, "Issue: Outdated Dependencies\n")
                details_text.insert(tk.END, "Details: The application uses libraries with known vulnerabilities.\n")
                details_text.insert(tk.END, "Recommendation: Update dependencies to the latest secure versions.\n\n")
        
        elif scan_type == "Web Scan":
            if "High" in findings:
                details_text.insert(tk.END, "=== HIGH SEVERITY ISSUES ===\n\n")
                details_text.insert(tk.END, "Issue: SQL Injection\n")
                details_text.insert(tk.END, "Details: The application is vulnerable to SQL injection at /search?query=\n")
                details_text.insert(tk.END, "Recommendation: Implement parameterized queries and input validation.\n\n")
            
            if "Medium" in findings:
                details_text.insert(tk.END, "=== MEDIUM SEVERITY ISSUES ===\n\n")
                details_text.insert(tk.END, "Issue: Cross-Site Scripting (XSS)\n")
                details_text.insert(tk.END, "Details: The website is vulnerable to XSS in the comment form.\n")
                details_text.insert(tk.END, "Recommendation: Implement output encoding and Content Security Policy.\n\n")
                
                details_text.insert(tk.END, "Issue: Missing Security Headers\n")
                details_text.insert(tk.END, "Details: The website is missing important security headers (X-XSS-Protection, X-Content-Type-Options).\n")
                details_text.insert(tk.END, "Recommendation: Configure web server to include all security headers.\n\n")
        
        # Add export button
        export_button = ttk.Button(details_window, text="Export Report", 
                                command=lambda: self.export_report(scan_type, target, date))
        export_button.pack(pady=10)
    
    def export_report(self, scan_type, target, date):
        # In a real app, this would export the actual report to different formats
        # For now, just show a message
        messagebox.showinfo("Export", f"Report for {target} ({scan_type}, {date}) would be exported here.")
    
    def update_status(self, message):
        def _update():
            self.status_var.set(message)
        self.root.after(0, _update)
    
    def update_file_results(self, message):
        def _update():
            self.file_results_text.insert(tk.END, message)
            self.file_results_text.see(tk.END)
        self.root.after(0, _update)
    
    def update_web_results(self, message):
        def _update():
            self.web_results_text.insert(tk.END, message)
            self.web_results_text.see(tk.END)
        self.root.after(0, _update)


# Scanner Classes
class VirusTotalScanner:
    """Scanner class for integrating with VirusTotal API."""
    
    def __init__(self, api_key):
        """Initialize VirusTotal scanner with API key.
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "User-Agent": "SecurityScannerMCP/1.0"
        }
        
    def set_api_key(self, api_key):
        """Update the API key.
        
        Args:
            api_key: New VirusTotal API key
        """
        self.api_key = api_key
        self.headers["x-apikey"] = self.api_key
        
    def scan_file(self, file_path):
        """Scan a file using VirusTotal API.
        
        Args:
            file_path: Path to file to be scanned
            
        Returns:
            dict: Scan results
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        if not self.api_key or self.api_key == '':
            return {"error": "VirusTotal API key not configured"}
        
        try:
            # Calculate file hash first to check if it already exists in VirusTotal
            file_hash = self._calculate_file_hash(file_path)
            
            # First, try to get report for existing file
            report_url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(report_url, headers=self.headers)
            
            if response.status_code == 200:
                # File was already analyzed, return the existing report
                result = response.json()
                return self._parse_virustotal_report(result)
            elif response.status_code == 404:
                # If file doesn't exist in VT, upload it for analysis
                upload_url = f"{self.base_url}/files"
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    upload_response = requests.post(upload_url, files=files, headers=self.headers)
                
                if upload_response.status_code == 200:
                    upload_result = upload_response.json()
                    scan_id = upload_result['data']['id']
                    
                    # Return the analysis ID for later retrieval
                    return {
                        "scan_id": scan_id,
                        "resource": file_hash,
                        "status": "submitted",
                        "message": "File submitted for analysis. Check back later for results."
                    }
                else:
                    return {"error": f"Upload failed with status code {upload_response.status_code}: {upload_response.text}"}
            else:
                return {"error": f"Request failed with status code {response.status_code}: {response.text}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            str: Hexadecimal digest of SHA-256 hash
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _parse_virustotal_report(self, response_data):
        """Parse VirusTotal API response into standardized format.
        
        Args:
            response_data: Raw response from VirusTotal API
            
        Returns:
            dict: Parsed and formatted results
        """
        try:
            attributes = response_data['data']['attributes']
            stats = attributes['stats']
            last_analysis_results = attributes['last_analysis_results']
            
            # Parse scan results
            scans = {}
            for engine, result in last_analysis_results.items():
                scans[engine] = {
                    "detected": result['category'] == 'malicious',
                    "result": result.get('result', None),
                    "version": result.get('engine_version', None)
                }
            
            return {
                "scan_id": response_data['data']['id'],
                "resource": response_data['data']['id'],
                "scan_date": attributes.get('last_analysis_date', ''),
                "permalink": attributes.get('permalink', ''),
                "total": stats.get('total', 0),
                "positives": stats.get('malicious', 0),
                "sha256": attributes.get('sha256', ''),
                "md5": attributes.get('md5', ''),
                "file_name": attributes.get('meaningful_name', ''),
                "file_size": attributes.get('size', 0),
                "scans": scans
            }
        except KeyError as e:
            return {"error": f"Unexpected response format: {str(e)}"}


class OWASPZAPScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "http://localhost:8080"
        self.zap = ZAPv2(
            apikey=self.api_key,
            proxies={'http': self.base_url, 'https': self.base_url}
        )
        
    def set_api_key(self, api_key):
        self.api_key = api_key
        self.zap = ZAPv2(
            apikey=self.api_key,
            proxies={'http': self.base_url, 'https': self.base_url}
        )
        
    def scan_url(self, url, options):
        """Scan a URL using OWASP ZAP"""
        if not self.api_key or self.api_key == '':
            return {"error": "OWASP ZAP API key not configured"}
        
        try:
            # Start the spider scan
            if options.get("crawl", False):
                spider_scan_id = self.zap.spider.scan(url)
                
                # Wait for spider to complete
                while int(self.zap.spider.status(spider_scan_id)) < 100:
                    time.sleep(5)  # Wait for 5 seconds before checking again
            
            # Run AJAX spider if requested
            if options.get("ajax", False):
                ajax_scan_id = self.zap.ajaxSpider.scan(url)
                
                # Wait for AJAX spider to complete
                while self.zap.ajaxSpider.status() not in ["stopped", "finished"]:
                    time.sleep(5)  # Wait for 5 seconds before checking again
            
            # Start the active scan
            scan_id = self.zap.ascan.scan(url)
            
            # Wait for active scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                time.sleep(10)  # Wait for 10 seconds before checking again
            
            # Get the alerts (vulnerabilities found)
            alerts = self.zap.core.alerts(baseurl=url)
            
            # Convert ZAP alerts to our standard format
            standardized_alerts = []
            for alert in alerts:
                standardized_alerts.append({
                    "alert": alert.get('alert', ''),
                    "risk": self._map_zap_risk_to_standard(alert.get('risk', '')),
                    "confidence": alert.get('confidence', ''),
                    "description": alert.get('description', ''),
                    "instances": [alert.get('url', url)],
                    "solution": alert.get('solution', ''),
                    "cweid": alert.get('cweid', ''),
                    "wascid": alert.get('wascid', '')
                })
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url,
                "alerts": standardized_alerts,
                "alert_count": len(standardized_alerts)
            }
            
        except Exception as e:
            return {"error": f"ZAP scan failed: {str(e)}"}
    
    def _map_zap_risk_to_standard(self, zap_risk):
        """Map ZAP risk levels to standard risk levels.
        
        Args:
            zap_risk: Risk level from ZAP (e.g., "High", "Medium", "Low", "Informational")
            
        Returns:
            Standardized risk level
        """
        risk_mapping = {
            "High": "High",
            "Medium": "Medium", 
            "Low": "Low",
            "Informational": "Info",
            "Information": "Info"
        }
        
        return risk_mapping.get(zap_risk, zap_risk)


class DependencyScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def set_api_key(self, api_key):
        self.api_key = api_key
        
    def scan_file(self, file_path):
        """Scan a file for vulnerable dependencies"""
        if not self.api_key:
            return {"error": "Dependency Scanner API key not configured"}
        
        try:
            # Extract dependencies from the file based on its type
            dependencies = self._extract_dependencies(file_path)
            
            # Check each dependency for vulnerabilities
            vulnerabilities = []
            for dep in dependencies:
                dep_vulns = self._check_dependency_vulnerabilities(dep["name"], dep["version"])
                vulnerabilities.extend(dep_vulns)
            
            return {
                "scan_id": f"dep-scan-{int(time.time())}",
                "file": file_path,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "dependencies": dependencies,
                "vulnerabilities": vulnerabilities,
                "summary": {
                    "total_dependencies": len(dependencies),
                    "vulnerable_dependencies": len(set(v["package"] for v in vulnerabilities)),
                    "high_severity": sum(1 for v in vulnerabilities if v["severity"].lower() in ["high", "critical"]),
                    "medium_severity": sum(1 for v in vulnerabilities if v["severity"].lower() == "medium"),
                    "low_severity": sum(1 for v in vulnerabilities if v["severity"].lower() == "low")
                }
            }
            
        except Exception as e:
            return {"error": f"Dependency scan failed: {str(e)}"}
    
    def _extract_dependencies(self, file_path):
        """Extract dependencies from the file based on the file type.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            List of dependencies with name and version
        """
        dependencies = []
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext in ['.py', '.pip']:
                dependencies = self._extract_python_dependencies(file_path)
            elif file_ext in ['.js', '.json'] and 'package.json' in file_path:
                dependencies = self._extract_npm_dependencies(file_path)
            elif file_ext in ['.xml'] and 'pom.xml' in file_path:
                dependencies = self._extract_maven_dependencies(file_path)
            elif file_ext in ['.gradle', '.properties'] and 'build.gradle' in file_path:
                dependencies = self._extract_gradle_dependencies(file_path)
            elif file_ext in ['.csproj', '.vbproj', '.props', '.targets']:
                dependencies = self._extract_nuget_dependencies(file_path)
            # For executable files, we could use other techniques to determine dependencies
            # but for this demo, we'll use a basic analysis based on file extension
            else:
                # If we can't parse the specific format, return an empty list
                # In a real implementation, we would analyze the binary for known library signatures
                pass
        except Exception:
            # If parsing fails, try to determine dependencies based on file extension
            pass
            
        return dependencies
    
    def _extract_python_dependencies(self, file_path):
        """Extract Python dependencies from requirements.txt or setup.py."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            # For requirements.txt files
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    # Split on common version specifiers
                    if "==" in line:
                        name, version = line.split("==", 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
                    elif ">=" in line:
                        name, version = line.split(">=", 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
                    elif "<=" in line:
                        name, version = line.split("<=", 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
                    elif ">" in line and not line.startswith(">"):  # Avoid lines starting with ">"
                        name, version = line.split(">", 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
                    elif "<" in line and not line.startswith("<"):  # Avoid lines starting with "<"
                        name, version = line.split("<", 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
                    else:
                        # Just the package name without version
                        dependencies.append({"name": line.strip(), "version": "unknown"})
        except Exception:
            # Fallback if file parsing fails
            pass
            
        return dependencies
    
    def _extract_npm_dependencies(self, file_path):
        """Extract NPM dependencies from package.json."""
        import json
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Get dependencies from both dependencies and devDependencies
            for dep_type in ["dependencies", "devDependencies"]:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        # Remove version specifier symbols like ^ or ~
                        clean_version = version.lstrip("^~>=<")
                        dependencies.append({"name": name, "version": clean_version})
        except Exception:
            # Fallback if JSON parsing fails
            pass
            
        return dependencies
    
    def _extract_maven_dependencies(self, file_path):
        """Extract Maven dependencies from pom.xml."""
        try:
            import xml.etree.ElementTree as ET
            dependencies = []
            
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Maven XML has namespaces, need to handle them
            namespace = {'m': 'http://maven.apache.org/POM/4.0.0'}
            
            for dep in root.findall(".//m:dependency", namespace):
                groupId = dep.find("m:groupId", namespace)
                artifactId = dep.find("m:artifactId", namespace)
                version = dep.find("m:version", namespace)
                
                if groupId is not None and artifactId is not None:
                    name = f"{groupId.text}:{artifactId.text}"
                    version_text = version.text if version is not None else "unknown"
                    dependencies.append({"name": name, "version": version_text})
                    
        except ImportError:
            # If xml module not available in this context
            pass
        except Exception:
            # If XML parsing fails
            pass
            
        return dependencies
    
    def _extract_gradle_dependencies(self, file_path):
        """Extract Gradle dependencies from build.gradle."""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            # Look for dependency declarations in Gradle format
            import re
            # Pattern matches: implementation 'group:name:version' or compile 'group:name:version'
            pattern = r'(?:implementation|compile|api|testImplementation)\s+[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]'
            matches = re.findall(pattern, content)
            
            for group, name, version in matches:
                full_name = f"{group}:{name}"
                dependencies.append({"name": full_name, "version": version})
        except Exception:
            # If parsing fails
            pass
            
        return dependencies
    
    def _extract_nuget_dependencies(self, file_path):
        """Extract NuGet dependencies from .csproj files."""
        dependencies = []
        
        try:
            import xml.etree.ElementTree as ET
            
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Look for PackageReference elements
            for package_ref in root.findall(".//PackageReference"):
                name = package_ref.get("Include")
                version = package_ref.get("Version")
                
                if name:
                    dependencies.append({"name": name, "version": version or "unknown"})
        except ImportError:
            # If xml module not available
            pass
        except Exception:
            # If XML parsing fails
            pass
            
        return dependencies
    
    def _check_dependency_vulnerabilities(self, package_name, version):
        """Check for vulnerabilities in a specific package version using NVD API.
        
        Args:
            package_name: Name of the package
            version: Version of the package
            
        Returns:
            List of vulnerabilities found for this package
        """
        vulnerabilities = []
        
        # For this implementation, we'll use the NVD API to search for CVEs
        # In a real implementation, you might use a service like OSS Index, Sonatype, or NVD
        try:
            # This is a simplified approach
            # In a real implementation, you would need to match specific package versions to CVEs
            params = {
                'keywordSearch': package_name
            }
            
            headers = {'User-Agent': 'SecurityScannerMCP/1.0'}
            response = requests.get(self.nvd_api_base, params=params, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                for cve_item in data.get('vulnerabilities', []):
                    cve = cve_item.get('cve', {})
                    cve_id = cve.get('id', '')
                    
                    # Simplified matching - in practice, you'd want to match exact package and version
                    # This is a limitation of the NVD API for package-specific version checks
                    # A better approach would be using a service like OSS Index or Sonatype
                    vulnerabilities.append({
                        "id": cve_id,
                        "package": package_name,
                        "version": version,
                        "severity": self._get_cve_severity(cve),
                        "description": self._get_cve_description(cve),
                        "recommendation": f"Check if version {version} is affected and upgrade if necessary"
                    })
        except Exception:
            # If NVD API call fails, return empty list
            # In a real implementation, you might want to try alternative sources
            pass
        
        return vulnerabilities
    
    def _get_cve_severity(self, cve_data):
        """Extract severity from CVE data."""
        try:
            metrics = cve_data.get('metrics', {})
            
            # Look for different possible CVSS versions
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                base_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                if float(base_score) >= 7.0:
                    severity = "High"
                elif float(base_score) >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"
            else:
                severity = "Unknown"
        except:
            severity = "Unknown"
        
        return severity
    
    def _get_cve_description(self, cve_data):
        """Extract description from CVE data."""
        try:
            descriptions = cve_data.get('descriptions', [])
            if descriptions:
                return descriptions[0].get('value', 'No description available')
        except:
            pass
        
        return "No description available"


# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityScannerMCP(root)
    root.mainloop()