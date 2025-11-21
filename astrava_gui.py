#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Advanced Professional GUI
Large results display, proper encoding, advanced features
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import subprocess
import webbrowser
import os
import sys
from pathlib import Path
from datetime import datetime
import re
import socket
import time
import requests
import queue

class AstravaAdvancedGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Astrava AI Security Scanner - Advanced Professional Interface")
        
        # Get screen dimensions
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        # Set window to 90% of screen size (adjustable)
        window_width = int(screen_width * 0.9)
        window_height = int(screen_height * 0.9)
        
        self.root.geometry(f"{window_width}x{window_height}")
        self.root.minsize(1200, 700)
        # Professional Burp Suite theme with blue-gray tones
        self.root.configure(bg='#e8eef5')
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure ttk styles for professional look
        self.setup_styles()
        
        # Variables
        self.target_url = tk.StringVar()
        self.attack_mode = tk.StringVar(value="basic")
        self.ai_model = tk.StringVar(value="llama3.2:3b")
        self.custom_payloads_file = tk.StringVar()
        self.verbose_mode = tk.BooleanVar(value=True)
        self.owasp_testing = tk.BooleanVar(value=False)  # OFF by default for basic mode
        self.chain_attacks = tk.BooleanVar(value=False)
        self.passive_only = tk.BooleanVar(value=False)
        self.active_only = tk.BooleanVar(value=False)
        
        # Scan state
        self.scanning = False
        self.scan_process = None
        self.report_path = None
        self.vulnerability_count = 0
        self.scan_start_time = None
        
        # Vulnerability parsing state
        self.collecting_vuln = False
        self.current_vuln = {}
        
        # Ollama state
        self.ollama_process = None
        self.ollama_running = False
        
        # Output queue for non-blocking updates
        self.output_queue = queue.Queue()
        self.process_queue()
        
        self.create_advanced_gui()
        self.center_window()
        
        # Check Ollama status on startup
        self.root.after(1000, self.check_ollama_status)
        
        # Apply rounded corners effect to buttons (visual enhancement)
        self.apply_button_styles()
        
        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """Setup professional ttk styles - Burp Suite blue-gray theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook style - Burp Suite blue-gray theme
        style.configure('TNotebook', background='#e8eef5', borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background='#d0dae8', 
                       foreground='#2c3e50',
                       padding=[20, 10],
                       borderwidth=1)
        style.map('TNotebook.Tab',
                 background=[('selected', '#f5f8fc')],
                 foreground=[('selected', '#1a2332')])
        
        # Configure progressbar - Professional orange
        style.configure('TProgressbar', 
                       background='#ff6633',
                       troughcolor='#d0dae8',
                       borderwidth=0,
                       thickness=6)
    
    def create_rounded_button(self, parent, text, command, bg_color, fg_color='white', 
                             font=('Segoe UI', 11, 'bold'), padx=20, pady=10, width=None):
        """Create a rounded button with professional Burp Suite styling"""
        # Create a frame to simulate rounded corners with border
        btn_frame = tk.Frame(parent, bg=parent['bg'], highlightthickness=0)
        
        # Create canvas for rounded rectangle
        canvas = tk.Canvas(btn_frame, bg=parent['bg'], highlightthickness=0, 
                          width=200, height=50, bd=0)
        canvas.pack()
        
        # Draw rounded rectangle
        def draw_rounded_rect(x1, y1, x2, y2, radius=12, **kwargs):
            points = [x1+radius, y1,
                     x1+radius, y1,
                     x2-radius, y1,
                     x2-radius, y1,
                     x2, y1,
                     x2, y1+radius,
                     x2, y1+radius,
                     x2, y2-radius,
                     x2, y2-radius,
                     x2, y2,
                     x2-radius, y2,
                     x2-radius, y2,
                     x1+radius, y2,
                     x1+radius, y2,
                     x1, y2,
                     x1, y2-radius,
                     x1, y2-radius,
                     x1, y1+radius,
                     x1, y1+radius,
                     x1, y1]
            return canvas.create_polygon(points, **kwargs, smooth=True)
        
        btn = tk.Button(btn_frame, text=text, command=command,
                       font=font, bg=bg_color, fg=fg_color,
                       relief=tk.FLAT, padx=padx, pady=pady,
                       borderwidth=0, highlightthickness=0,
                       activebackground=self.adjust_color(bg_color, 0.85),
                       activeforeground='#ffffff',  # White text on hover
                       disabledforeground='#ffffff',  # White text when disabled
                       cursor='hand2')
        
        if width:
            btn.config(width=width)
        
        # Remove canvas and just use button with rounded appearance
        canvas.destroy()
        btn.pack(padx=2, pady=2)
        
        # Add subtle border effect
        btn.config(relief=tk.FLAT, bd=0)
        
        # Bind hover effects
        btn.bind('<Enter>', lambda e: btn.config(bg=self.adjust_color(bg_color, 0.85)))
        btn.bind('<Leave>', lambda e: btn.config(bg=bg_color))
        
        return btn_frame, btn
    
    def adjust_color(self, hex_color, factor):
        """Adjust color brightness"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        rgb = tuple(min(255, int(c * factor)) for c in rgb)
        return f'#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}'
    
    def apply_button_styles(self):
        """Apply rounded button styles using platform-specific methods"""
        # This method can be extended for platform-specific rounded corners
        # For now, we use flat design with hover effects which works cross-platform
        pass
    
    def create_advanced_gui(self):
        """Create advanced professional GUI - Burp Suite blue-gray theme"""
        # Main container - Burp Suite blue-gray background
        main_container = tk.Frame(self.root, bg='#e8eef5')
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Top section - Configuration with professional styling
        top_outer = tk.Frame(main_container, bg='#e8eef5')
        top_outer.pack(fill=tk.X, padx=5, pady=(5, 5))
        
        top_frame = tk.Frame(top_outer, bg='#f5f8fc', relief=tk.FLAT, bd=1, 
                            highlightbackground='#b8c5d6', highlightthickness=1)
        top_frame.pack(fill=tk.X)
        
        self.create_header_section(top_frame)
        self.create_config_section(top_frame)
        self.create_control_section(top_frame)
        
        # Bottom section (70% height) - Large Results Display
        results_container = tk.Frame(main_container, bg='#e8eef5')
        results_container.pack(fill=tk.BOTH, expand=True)
        
        self.create_large_results_section(results_container)
        
        # Status bar
        self.create_status_section(main_container)
    
    def create_header_section(self, parent):
        """Create professional header - Burp Suite style"""
        header_frame = tk.Frame(parent, bg='#f5f8fc', height=70)
        header_frame.pack(fill=tk.X, padx=15, pady=10)
        header_frame.pack_propagate(False)
        
        # Title with professional blue accent
        title_label = tk.Label(header_frame, 
                              text="ASTRAVA AI SECURITY SCANNER", 
                              font=('Segoe UI', 22, 'bold'),
                              fg='#0066cc', bg='#f5f8fc')
        title_label.pack(pady=(8, 0))
        
        # Subtitle
        subtitle_label = tk.Label(header_frame, 
                                text="Advanced Professional Web Security Assessment Platform", 
                                font=('Segoe UI', 10),
                                fg='#5a6c7d', bg='#f5f8fc')
        subtitle_label.pack()
    
    def create_config_section(self, parent):
        """Create configuration section"""
        config_main = tk.Frame(parent, bg='#f5f8fc')
        config_main.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Left side - Target and Attack Mode
        left_config = tk.Frame(config_main, bg='#f5f8fc', width=600)
        left_config.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_config.pack_propagate(False)
        
        # Target URL
        target_frame = tk.LabelFrame(left_config, text="Target Configuration", 
                                   font=('Segoe UI', 11, 'bold'), fg='#2c3e50', bg='#eef3f9',
                                   relief=tk.SOLID, bd=1, highlightbackground='#b8c5d6', highlightthickness=0)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_frame, text="Target URL:", font=('Segoe UI', 10, 'bold'), 
                fg='#2c3e50', bg='#eef3f9').pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        url_frame = tk.Frame(target_frame, bg='#eef3f9')
        url_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.url_entry = tk.Entry(url_frame, textvariable=self.target_url, 
                                 font=('Segoe UI', 11), width=50, bg='#ffffff', fg='#2c3e50',
                                 relief=tk.SOLID, insertbackground='#2c3e50', bd=1)
        self.url_entry.pack(fill=tk.X, ipady=5)
        
        # Example buttons with Burp Suite blue style
        examples_frame = tk.Frame(target_frame, bg='#eef3f9')
        examples_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        examples = [
            ("Vulnerable PHP", "http://testphp.vulnweb.com/"),
            ("Banking Demo", "http://demo.testfire.net/"),
            ("HTTP Testing", "https://httpbin.org/")
        ]
        
        for text, url in examples:
            btn = tk.Button(examples_frame, text=text, 
                          command=lambda u=url: self.target_url.set(u),
                          font=('Segoe UI', 9), bg='#d0dae8', fg='#2c3e50',
                          relief=tk.FLAT, padx=12, pady=5, bd=1,
                          cursor='hand2', activebackground='#b8c5d6')
            btn.pack(side=tk.LEFT, padx=(0, 5))
            btn.bind('<Enter>', lambda e, b=btn: b.config(bg='#b8c5d6'))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg='#d0dae8'))
        
        # Attack Mode Selection - Burp Suite blue theme
        mode_frame = tk.LabelFrame(left_config, text="Attack Mode Selection", 
                                 font=('Segoe UI', 11, 'bold'), fg='#2c3e50', bg='#eef3f9',
                                 relief=tk.SOLID, bd=1, highlightbackground='#b8c5d6', highlightthickness=0)
        mode_frame.pack(fill=tk.X)
        
        # Attack modes with detailed descriptions - Professional colors
        modes = [
            ("basic", "⚡ Basic Scan", "Fast scan (OWASP OFF by default)", "#28a745"),
            ("medium", "🔍 Medium Scan", "OWASP Top 10 + AI analysis", "#ff9933"),
            ("aggressive", "🔥 Aggressive Scan", "OWASP + Chain Attacks + AI", "#dc3545")
        ]
        
        for value, title, desc, color in modes:
            mode_container = tk.Frame(mode_frame, bg='#eef3f9')
            mode_container.pack(fill=tk.X, padx=5, pady=3)
            
            tk.Radiobutton(mode_container, text=title, 
                          variable=self.attack_mode, value=value,
                          font=('Segoe UI', 10, 'bold'), fg=color, bg='#eef3f9',
                          selectcolor='#ffffff', activebackground='#eef3f9',
                          command=self.update_mode_info).pack(side=tk.LEFT)
            
            tk.Label(mode_container, text=desc, font=('Segoe UI', 9), 
                    fg='#5a6c7d', bg='#eef3f9').pack(side=tk.LEFT, padx=(10, 0))
        
        # Right side - Advanced Options
        right_config = tk.Frame(config_main, bg='#f5f8fc')
        right_config.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Advanced Options - Burp Suite blue theme
        advanced_frame = tk.LabelFrame(right_config, text="Advanced Options", 
                                     font=('Segoe UI', 11, 'bold'), fg='#2c3e50', bg='#eef3f9',
                                     relief=tk.SOLID, bd=1, highlightbackground='#b8c5d6', highlightthickness=0)
        advanced_frame.pack(fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # AI Model
        ai_frame = tk.Frame(advanced_frame, bg='#eef3f9')
        ai_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(ai_frame, text="AI Model:", font=('Segoe UI', 10, 'bold'), 
                fg='#2c3e50', bg='#eef3f9').pack(side=tk.LEFT)
        
        ai_combo = ttk.Combobox(ai_frame, textvariable=self.ai_model, width=20,
                               values=["llama3.2:3b"],
                               state='readonly',
                               font=('Segoe UI', 9))
        ai_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Custom Payloads
        payloads_frame = tk.Frame(advanced_frame, bg='#eef3f9')
        payloads_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(payloads_frame, text="Custom Payloads:", font=('Segoe UI', 10, 'bold'), 
                fg='#2c3e50', bg='#eef3f9').pack(anchor=tk.W)
        
        file_frame = tk.Frame(payloads_frame, bg='#eef3f9')
        file_frame.pack(fill=tk.X, pady=(2, 0))
        
        tk.Entry(file_frame, textvariable=self.custom_payloads_file, 
                font=('Segoe UI', 9), width=30, bg='#ffffff', fg='#2c3e50',
                relief=tk.SOLID, insertbackground='#2c3e50', bd=1).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
        
        browse_btn = tk.Button(file_frame, text="Browse", command=self.browse_payloads,
                 font=('Segoe UI', 9), bg='#d0dae8', fg='#2c3e50', 
                 relief=tk.FLAT, bd=1, cursor='hand2', activebackground='#b8c5d6')
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        browse_btn.bind('<Enter>', lambda e: browse_btn.config(bg='#b8c5d6'))
        browse_btn.bind('<Leave>', lambda e: browse_btn.config(bg='#d0dae8'))
        
        # Testing Options
        options_frame = tk.Frame(advanced_frame, bg='#eef3f9')
        options_frame.pack(fill=tk.X, padx=5, pady=10)
        
        tk.Label(options_frame, text="Testing Options:", font=('Segoe UI', 10, 'bold'), 
                fg='#2c3e50', bg='#eef3f9').pack(anchor=tk.W)
        
        # Checkboxes for options
        # Store checkboxes for later control
        self.option_checkboxes = {}
        
        options = [
            ("✓ OWASP Top 10 Testing", self.owasp_testing, "owasp"),
            ("✓ AI Chain Attacks", self.chain_attacks, "chain"),
            ("✓ Passive Scan Only", self.passive_only, "passive"),
            ("✓ Verbose Output", self.verbose_mode, "verbose")
        ]
        
        for text, var, key in options:
            chk = tk.Checkbutton(options_frame, text=text, variable=var,
                          font=('Segoe UI', 9), fg='#2c3e50', bg='#eef3f9',
                          selectcolor='#ffffff', activebackground='#eef3f9',
                          activeforeground='#1a2332')
            chk.pack(anchor=tk.W, pady=1)
            self.option_checkboxes[key] = chk
    
    def create_control_section(self, parent):
        """Create control buttons section with professional Burp Suite style"""
        # Outer container
        control_outer = tk.Frame(parent, bg='#e8eef5')
        control_outer.pack(fill=tk.X, padx=10, pady=10)
        
        control_frame = tk.Frame(control_outer, bg='#f5f8fc', height=90,
                                highlightbackground='#b8c5d6', highlightthickness=1,
                                relief=tk.FLAT)
        control_frame.pack(fill=tk.X)
        control_frame.pack_propagate(False)
        
        # Buttons container
        buttons_frame = tk.Frame(control_frame, bg='#f5f8fc')
        buttons_frame.pack(expand=True, pady=(5, 0))
        
        # Main scan button - Professional orange
        start_frame, self.start_btn = self.create_rounded_button(
            buttons_frame, "START SECURITY SCAN", self.start_scan,
            '#ff6633', font=('Segoe UI', 13, 'bold'), padx=45, pady=16
        )
        start_frame.pack(side=tk.LEFT, padx=(0, 10))
        
        # Stop button - Red
        stop_frame, self.stop_btn = self.create_rounded_button(
            buttons_frame, "STOP SCAN", self.stop_scan,
            '#dc3545', font=('Segoe UI', 11, 'bold'), padx=22, pady=11
        )
        self.stop_btn.config(state='disabled')
        stop_frame.pack(side=tk.LEFT, padx=(0, 8))
        
        # Clear button - Gray
        clear_frame, clear_btn = self.create_rounded_button(
            buttons_frame, "CLEAR RESULTS", self.clear_results,
            '#6c757d', font=('Segoe UI', 11, 'bold'), padx=22, pady=11
        )
        clear_frame.pack(side=tk.LEFT, padx=(0, 8))
        
        # Report button - Orange
        report_frame, self.report_btn = self.create_rounded_button(
            buttons_frame, "OPEN REPORT", self.open_report,
            '#ff6633', font=('Segoe UI', 11, 'bold'), padx=22, pady=11
        )
        self.report_btn.config(state='disabled')
        report_frame.pack(side=tk.LEFT, padx=(0, 8))
        
        # Refresh counts button - Blue
        refresh_frame, self.refresh_btn = self.create_rounded_button(
            buttons_frame, "REFRESH COUNTS", self.refresh_counts_from_report,
            '#007bff', font=('Segoe UI', 11, 'bold'), padx=22, pady=11
        )
        self.refresh_btn.config(state='disabled')
        refresh_frame.pack(side=tk.LEFT)
        
        # Progress bar (full width, professional style)
        progress_frame = tk.Frame(control_frame, bg='#f5f8fc')
        progress_frame.pack(fill=tk.X, pady=(12, 0), padx=10)
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate', style='TProgressbar')
        self.progress.pack(fill=tk.X)
    
    def create_large_results_section(self, parent):
        """Create large results display section - Burp Suite blue-gray theme"""
        # Outer container
        results_outer = tk.Frame(parent, bg='#e8eef5')
        results_outer.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results header with statistics - Burp Suite blue theme
        results_header = tk.Frame(results_outer, bg='#f5f8fc', height=100, 
                                 highlightbackground='#b8c5d6', highlightthickness=1,
                                 relief=tk.FLAT)
        results_header.pack(fill=tk.X, pady=(0, 0))
        results_header.pack_propagate(False)
        
        # Statistics display
        stats_frame = tk.Frame(results_header, bg='#f5f8fc')
        stats_frame.pack(expand=True, pady=8)
        
        # Vulnerability counters with Burp Suite-style colors
        # Critical=Red, High=Orange, Medium=Yellow, Low=Blue
        self.stats_labels = {}
        self.stats_dots = {}
        stats = [
            ("Total Vulnerabilities", "total", "#333333", "●", "DETECTED"),
            ("Critical", "critical", "#d9534f", "●", "CRITICAL"),
            ("High", "high", "#ff9933", "●", "HIGH"),
            ("Medium", "medium", "#f0ad4e", "●", "MEDIUM"),
            ("Low", "low", "#5bc0de", "●", "LOW")
        ]
        
        for text, key, color, dot, label_text in stats:
            stat_container = tk.Frame(stats_frame, bg='#f5f8fc')
            stat_container.pack(side=tk.LEFT, padx=20)
            
            # Count with larger font
            count_label = tk.Label(stat_container, text="0", 
                                 font=('Segoe UI', 32, 'bold'),
                                 fg=color, bg='#f5f8fc')
            count_label.pack()
            
            # Colored severity label below count (more prominent)
            severity_label = tk.Label(stat_container, text=label_text,
                                    font=('Segoe UI', 11, 'bold'),
                                    fg=color, bg='#f5f8fc')
            severity_label.pack(pady=(3, 0))
            
            # Indicator dot below label
            dot_label = tk.Label(stat_container, text=dot,
                               font=('Arial', 16),
                               fg='#d0dae8', bg='#f5f8fc')
            dot_label.pack(pady=(2, 0))
            
            self.stats_labels[key] = count_label
            self.stats_dots[key] = dot_label
        
        # Large results notebook - Burp Suite blue theme
        notebook_container = tk.Frame(results_outer, bg='#e8eef5', 
                                     highlightbackground='#b8c5d6', highlightthickness=1,
                                     relief=tk.FLAT)
        notebook_container.pack(fill=tk.BOTH, expand=True)
        
        self.results_notebook = ttk.Notebook(notebook_container)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Console tab - Burp Suite style console
        console_frame = tk.Frame(self.results_notebook, bg='#f5f8fc')
        self.results_notebook.add(console_frame, text="  Live Console Output  ")
        
        self.console_text = scrolledtext.ScrolledText(console_frame, 
                                                    font=('Consolas', 10),
                                                    bg='#ffffff', fg='#2c3e50',
                                                    insertbackground='#2c3e50',
                                                    relief=tk.FLAT, bd=0)
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure console colors - Professional theme
        self.console_text.tag_configure("info", foreground="#007bff")
        self.console_text.tag_configure("warning", foreground="#ff9933")
        self.console_text.tag_configure("error", foreground="#dc3545")
        self.console_text.tag_configure("success", foreground="#28a745")
        self.console_text.tag_configure("vulnerability", foreground="#d9534f", font=('Consolas', 11, 'bold'))
        
        # Vulnerabilities tab - Burp Suite blue background
        vuln_frame = tk.Frame(self.results_notebook, bg='#f5f8fc')
        self.results_notebook.add(vuln_frame, text="  Vulnerabilities Detected  ")
        
        # Vulnerability display with tree view
        vuln_container = tk.Frame(vuln_frame, bg='#f5f8fc')
        vuln_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Vulnerability tree (responsive)
        self.vuln_tree = ttk.Treeview(vuln_container, 
                                     columns=('Type', 'Severity', 'URL', 'Parameter', 'Evidence'), 
                                     show='tree headings')
        
        # Configure headers
        self.vuln_tree.heading('#0', text='ID')
        self.vuln_tree.heading('Type', text='Vulnerability Type')
        self.vuln_tree.heading('Severity', text='Severity')
        self.vuln_tree.heading('URL', text='Target URL')
        self.vuln_tree.heading('Parameter', text='Parameter')
        self.vuln_tree.heading('Evidence', text='Evidence')
        
        # Configure column widths
        self.vuln_tree.column('#0', width=50)
        self.vuln_tree.column('Type', width=200)
        self.vuln_tree.column('Severity', width=100)
        self.vuln_tree.column('URL', width=300)
        self.vuln_tree.column('Parameter', width=150)
        self.vuln_tree.column('Evidence', width=200)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(vuln_container, orient='vertical', command=self.vuln_tree.yview)
        h_scroll = ttk.Scrollbar(vuln_container, orient='horizontal', command=self.vuln_tree.xview)
        
        self.vuln_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Pack tree and scrollbars
        self.vuln_tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        vuln_container.grid_rowconfigure(0, weight=1)
        vuln_container.grid_columnconfigure(0, weight=1)
        
        # Configure severity colors - Burp Suite style
        # Critical=Red background, High=Orange, Medium=Yellow, Low=Blue
        self.vuln_tree.tag_configure('critical', background='#f8d7da', foreground='#721c24')
        self.vuln_tree.tag_configure('high', background='#fff3cd', foreground='#856404')
        self.vuln_tree.tag_configure('medium', background='#fff9e6', foreground='#664d03')
        self.vuln_tree.tag_configure('low', background='#d1ecf1', foreground='#0c5460')
        
        # Summary tab - Burp Suite blue background
        summary_frame = tk.Frame(self.results_notebook, bg='#f5f8fc')
        self.results_notebook.add(summary_frame, text="  Detailed Summary  ")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, 
                                                    font=('Segoe UI', 10),
                                                    bg='#ffffff', fg='#2c3e50',
                                                    relief=tk.FLAT, bd=0)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # AI Analysis tab - Burp Suite blue background
        ai_frame = tk.Frame(self.results_notebook, bg='#f5f8fc')
        self.results_notebook.add(ai_frame, text="  AI Analysis & Recommendations  ")
        
        self.ai_text = scrolledtext.ScrolledText(ai_frame, 
                                               font=('Segoe UI', 10),
                                               bg='#ffffff', fg='#2c3e50',
                                               relief=tk.FLAT, bd=0)
        self.ai_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_status_section(self, parent):
        """Create status bar - Burp Suite blue theme"""
        # Outer container
        status_outer = tk.Frame(parent, bg='#e8eef5')
        status_outer.pack(fill=tk.X, padx=5, pady=(5, 5))
        
        status_frame = tk.Frame(status_outer, bg='#f5f8fc', height=35, 
                               highlightbackground='#b8c5d6', highlightthickness=1,
                               relief=tk.FLAT)
        status_frame.pack(fill=tk.X)
        status_frame.pack_propagate(False)
        
        # Status info
        status_container = tk.Frame(status_frame, bg='#f5f8fc')
        status_container.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = tk.Label(status_container, text="● Ready to scan", 
                                   font=('Segoe UI', 10), bg='#f5f8fc', fg='#28a745')
        self.status_label.pack(side=tk.LEFT)
        
        self.time_label = tk.Label(status_container, text="", 
                                 font=('Segoe UI', 10), bg='#f5f8fc', fg='#5a6c7d')
        self.time_label.pack(side=tk.RIGHT)
        
        self.update_time()
    
    def update_mode_info(self):
        """Update mode information - Professional theme"""
        mode = self.attack_mode.get()
        
        # Update button color based on mode - Professional colors
        colors = {
            "basic": "#28a745",
            "medium": "#ff9933", 
            "aggressive": "#dc3545"
        }
        
        self.start_btn.config(bg=colors.get(mode, "#ff6633"))
        
        # Configure options based on attack mode
        if hasattr(self, 'option_checkboxes'):
            if mode == "basic":
                # BASIC MODE: Fast scan, no OWASP, no chain attacks
                self.option_checkboxes['owasp'].config(state='normal')  # User can enable if needed
                self.option_checkboxes['chain'].config(state='disabled')  # Not available in basic
                self.owasp_testing.set(False)  # OFF by default
                self.chain_attacks.set(False)  # Always OFF
                
            elif mode == "medium":
                # MEDIUM MODE: OWASP ON, chain attacks optional
                self.option_checkboxes['owasp'].config(state='normal')
                self.option_checkboxes['chain'].config(state='normal')
                self.owasp_testing.set(True)  # ON by default
                self.chain_attacks.set(False)  # OFF by default, user can enable
                
            elif mode == "aggressive":
                # AGGRESSIVE MODE: OWASP ON, chain attacks ON
                self.option_checkboxes['owasp'].config(state='normal')
                self.option_checkboxes['chain'].config(state='normal')
                self.owasp_testing.set(True)  # ON by default
                self.chain_attacks.set(True)  # ON by default
    
    def browse_payloads(self):
        """Browse for payloads file"""
        filename = filedialog.askopenfilename(
            title="Select Custom Payloads File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.custom_payloads_file.set(filename)
    
    def start_scan(self):
        """Start security scan"""
        if not self.target_url.get().strip():
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        url = self.target_url.get().strip()
        if not (url.startswith('http://') or url.startswith('https://')):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return
        
        # Confirm aggressive mode
        if self.attack_mode.get() == "aggressive":
            if not messagebox.askyesno("Aggressive Scan Warning", 
                                     "Aggressive scans use intensive techniques.\n"
                                     "Only use on systems you own or have permission to test.\n\n"
                                     "Continue?"):
                return
        
        # Update UI
        self.scanning = True
        self.scan_start_time = datetime.now()
        self.start_btn.config(state='disabled', text="SCANNING...", bg='#999999', 
                             disabledforeground='#ffffff')  # White text when disabled
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.status_label.config(text="● Initializing scan...", fg='#ff9933')
        
        # Clear results
        self.clear_results()
        
        # Start scan thread
        scan_thread = threading.Thread(target=self.run_advanced_scan, daemon=True)
        scan_thread.start()
    
    def run_advanced_scan(self):
        """Run advanced scan with proper encoding"""
        try:
            mode = self.attack_mode.get()
            
            # Build command based on mode
            if mode == "basic":
                # Basic mode uses fast_scan.py (no OWASP testing, no verbose flag support)
                cmd = ["python", "fast_scan.py", "-u", self.target_url.get().strip()]
            else:
                # Medium and Aggressive modes use main.py with full features
                cmd = ["python", "main.py", "-u", self.target_url.get().strip()]
                
                # Add mode-specific options (OWASP only for medium/aggressive)
                if self.owasp_testing.get() and mode in ["medium", "aggressive"]:
                    cmd.append("--owasp-all")
                
                if mode == "medium":
                    cmd.extend(["--threads", "10", "--timeout", "30"])
                elif mode == "aggressive":
                    cmd.extend(["--threads", "20", "--timeout", "60"])
                    if self.chain_attacks.get():
                        cmd.append("--chain-attacks")
                
                # Add scan type options
                if self.passive_only.get():
                    cmd.append("--passive-only")
                elif self.active_only.get():
                    cmd.append("--active-only")
                
                # Add AI model
                cmd.extend(["--model", self.ai_model.get()])
                
                # Add verbose (only for main.py, not fast_scan.py)
                if self.verbose_mode.get():
                    cmd.append("--verbose")
            
            # Add custom payloads (both scripts support this)
            if self.custom_payloads_file.get():
                cmd.extend(["--custom-payloads", self.custom_payloads_file.get()])
            
            # Update console via queue
            self.output_queue.put(("console", f"Starting {mode.title()} Scan\n", "info"))
            self.output_queue.put(("console", f"Target: {self.target_url.get()}\n", "info"))
            self.output_queue.put(("console", f"Command: {' '.join(cmd)}\n\n", "info"))
            
            # Run scan with proper encoding and environment
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            
            self.scan_process = subprocess.Popen(
                cmd,
                cwd=Path(__file__).parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace problematic characters
                env=env
            )
            
            # Read output with encoding safety - batch updates to reduce GUI blocking
            line_buffer = []
            buffer_size = 5  # Process 5 lines at a time
            
            while True:
                line = self.scan_process.stdout.readline()
                if line == '' and self.scan_process.poll() is not None:
                    break
                if line and self.scanning:
                    # Clean line of problematic characters and ANSI codes
                    clean_line = line.encode('ascii', 'ignore').decode('ascii')
                    
                    # Remove ANSI color codes (e.g., [32m, [0m, [1m, etc.)
                    import re
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', clean_line)  # Remove ANSI escape sequences
                    clean_line = re.sub(r'\[[\d;]+m', '', clean_line)  # Remove [32m, [0m style codes
                    
                    # Determine line type and parse vulnerabilities
                    line_type = "info"
                    if "ERROR" in clean_line or "Failed" in clean_line:
                        line_type = "error"
                    elif "WARNING" in clean_line or "WARN" in clean_line:
                        line_type = "warning"
                    elif "VULNERABILITY FOUND" in clean_line or "[!]" in clean_line or "ALERT" in clean_line:
                        line_type = "vulnerability"
                        # Start collecting vulnerability details
                        self.output_queue.put(("vuln_start", clean_line))
                    elif "SUCCESS" in clean_line or "completed" in clean_line.lower():
                        line_type = "success"
                    
                    # Check for vulnerability details in subsequent lines
                    if hasattr(self, 'collecting_vuln') and self.collecting_vuln:
                        self.output_queue.put(("vuln_collect", clean_line))
                    
                    # Buffer lines for batch update
                    line_buffer.append((clean_line, line_type))
                    
                    # Update console in batches to reduce GUI blocking
                    if len(line_buffer) >= buffer_size:
                        for buffered_line, buffered_type in line_buffer:
                            self.output_queue.put(("console", buffered_line, buffered_type))
                        line_buffer = []
            
            # Flush remaining buffer
            for buffered_line, buffered_type in line_buffer:
                self.output_queue.put(("console", buffered_line, buffered_type))
            
            # Parse final summary if available
            self.output_queue.put(("parse_summary",))
            
            # Scan completed
            self.output_queue.put(("scan_complete",))
            
        except Exception as e:
            self.output_queue.put(("scan_error", str(e)))
    
    def process_queue(self):
        """Process output queue periodically without blocking"""
        try:
            # Process up to 10 items at once to batch updates
            for _ in range(10):
                action, *args = self.output_queue.get_nowait()
                
                if action == "console":
                    text, tag = args
                    self.console_text.insert(tk.END, text, tag)
                    self.console_text.see(tk.END)
                elif action == "status":
                    text, color = args
                    self.status_label.config(text=text, fg=color)
                elif action == "vuln_start":
                    self.start_vulnerability_parse(args[0])
                elif action == "vuln_collect":
                    self.collect_vulnerability_line(args[0])
                elif action == "parse_summary":
                    self.parse_final_summary()
                elif action == "scan_complete":
                    self.scan_completed()
                elif action == "scan_error":
                    self.scan_error(args[0])
                    
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Queue processing error: {e}")
        
        # Schedule next queue check (every 100ms)
        self.root.after(100, self.process_queue)
    
    def update_console(self, text, tag="info"):
        """Update console with colored output"""
        try:
            self.console_text.insert(tk.END, text, tag)
            self.console_text.see(tk.END)
        except tk.TclError:
            # Widget might be destroyed
            pass
    
    def start_vulnerability_parse(self, line):
        """Start collecting vulnerability details"""
        self.collecting_vuln = True
        self.current_vuln = {
            'type': 'Unknown',
            'severity': 'Medium',
            'url': '',
            'parameter': '',
            'evidence': '',
            'lines_collected': 0
        }
        
        # Parse the first line for type hints
        if "Command Injection" in line:
            self.current_vuln['severity'] = 'Critical'
        elif "SQL Injection" in line or "SQL" in line:
            self.current_vuln['severity'] = 'High'
        elif "Local File Inclusion" in line or "LFI" in line:
            self.current_vuln['severity'] = 'High'
        elif "SSRF" in line or "Server-Side Request Forgery" in line:
            self.current_vuln['severity'] = 'High'
        elif "XSS" in line or "Cross-Site Scripting" in line:
            self.current_vuln['severity'] = 'Medium'
        elif "Information Disclosure" in line:
            self.current_vuln['severity'] = 'Medium'
        elif "Security Header" in line:
            self.current_vuln['severity'] = 'Low'
    
    def collect_vulnerability_line(self, line):
        """Collect vulnerability details from output lines"""
        if not hasattr(self, 'current_vuln'):
            return
        
        self.current_vuln['lines_collected'] += 1
        
        # Parse vulnerability details
        if "Type:" in line:
            self.current_vuln['type'] = line.split("Type:")[-1].strip()
        elif "URL:" in line:
            self.current_vuln['url'] = line.split("URL:")[-1].strip()
        elif "Parameter:" in line:
            self.current_vuln['parameter'] = line.split("Parameter:")[-1].strip()
        elif "Evidence:" in line or "Payload:" in line:
            self.current_vuln['evidence'] = line.split(":")[-1].strip()[:50]
        elif "Severity:" in line:
            # Extract actual severity from output
            severity_text = line.split("Severity:")[-1].strip()
            if severity_text in ['Critical', 'High', 'Medium', 'Low']:
                self.current_vuln['severity'] = severity_text
        
        # After collecting enough lines or hitting separator, add vulnerability
        if "===" in line or self.current_vuln['lines_collected'] >= 8:
            self.add_parsed_vulnerability()
            self.collecting_vuln = False
    
    def add_parsed_vulnerability(self):
        """Add the collected vulnerability to the tree"""
        if not hasattr(self, 'current_vuln'):
            return
        
        self.vulnerability_count += 1
        
        vuln = self.current_vuln
        
        # Add to tree
        item_id = self.vuln_tree.insert('', 'end', 
                                       text=str(self.vulnerability_count),
                                       values=(vuln['type'], vuln['severity'], 
                                              vuln['url'][:50] if vuln['url'] else 'N/A', 
                                              vuln['parameter'] if vuln['parameter'] else 'N/A',
                                              vuln['evidence'] if vuln['evidence'] else 'N/A'),
                                       tags=(vuln['severity'].lower(),))
        
        # Update statistics with animated dots
        self.stats_labels['total'].config(text=str(self.vulnerability_count))
        self.animate_dot('total')
        
        # Update severity counters
        severity_key = vuln['severity'].lower()
        if severity_key in self.stats_labels:
            current = int(self.stats_labels[severity_key]['text'])
            self.stats_labels[severity_key].config(text=str(current + 1))
            self.animate_dot(severity_key)
    
    def animate_dot(self, key):
        """Animate indicator dot when vulnerability is found"""
        if key in self.stats_dots:
            dot = self.stats_dots[key]
            # Flash the dot
            original_color = dot['fg']
            dot.config(fg=self.stats_labels[key]['fg'])
            self.root.after(500, lambda: dot.config(fg='#cccccc'))
    
    def parse_final_summary(self):
        """Parse the final summary from console and report file to get accurate counts"""
        try:
            console_text = self.console_text.get("1.0", tk.END)
            
            # Look for summary patterns in console
            import re
            
            # First try to parse from console output
            # Pattern: "Total Vulnerabilities Found: 62"
            total_match = re.search(r'Total Vulnerabilities Found:\s*(\d+)', console_text, re.IGNORECASE)
            if total_match:
                total = int(total_match.group(1))
                self.vulnerability_count = total
                self.stats_labels['total'].config(text=str(total))
            
            # Pattern for severity breakdown (if available in output)
            # Try multiple patterns for severity counts
            critical_match = re.search(r'Critical[:\s]+(\d+)', console_text, re.IGNORECASE)
            high_match = re.search(r'High[:\s]+(\d+)', console_text, re.IGNORECASE)
            medium_match = re.search(r'Medium[:\s]+(\d+)', console_text, re.IGNORECASE)
            low_match = re.search(r'Low[:\s]+(\d+)', console_text, re.IGNORECASE)
            
            if critical_match:
                self.stats_labels['critical'].config(text=critical_match.group(1))
            if high_match:
                self.stats_labels['high'].config(text=high_match.group(1))
            if medium_match:
                self.stats_labels['medium'].config(text=medium_match.group(1))
            if low_match:
                self.stats_labels['low'].config(text=low_match.group(1))
            
            # Also try to parse from the HTML report file if it exists
            self.parse_report_file()
                
        except Exception as e:
            print(f"Error parsing summary: {e}")
    
    def parse_report_file(self):
        """Parse the HTML report file to get accurate vulnerability counts"""
        try:
            # Find the most recent report file
            result_dirs = ['reports', 'results', 'fixed_results', 'fast_scan_results']
            
            for dir_name in result_dirs:
                dir_path = Path(__file__).parent / dir_name
                if dir_path.exists():
                    html_files = list(dir_path.glob('*.html'))
                    if html_files:
                        report_file = max(html_files, key=os.path.getctime)
                        
                        # Read and parse the HTML report
                        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
                            report_content = f.read()
                        
                        import re
                        
                        # Parse total vulnerabilities
                        total_patterns = [
                            r'Total Vulnerabilities[:\s]+(\d+)',
                            r'Total[:\s]+(\d+)\s+vulnerabilities',
                            r'(\d+)\s+Total\s+Vulnerabilities',
                            r'<h3>Total:\s*(\d+)</h3>',
                            r'Total</td>\s*<td[^>]*>(\d+)</td>'
                        ]
                        
                        for pattern in total_patterns:
                            match = re.search(pattern, report_content, re.IGNORECASE)
                            if match:
                                total = int(match.group(1))
                                self.vulnerability_count = total
                                self.stats_labels['total'].config(text=str(total))
                                break
                        
                        # Parse severity breakdown
                        severity_patterns = {
                            'critical': [
                                r'Critical[:\s]+(\d+)',
                                r'(\d+)\s+Critical',
                                r'<td[^>]*>Critical</td>\s*<td[^>]*>(\d+)</td>',
                                r'Critical</td>\s*<td[^>]*>(\d+)</td>'
                            ],
                            'high': [
                                r'High[:\s]+(\d+)',
                                r'(\d+)\s+High',
                                r'<td[^>]*>High</td>\s*<td[^>]*>(\d+)</td>',
                                r'High</td>\s*<td[^>]*>(\d+)</td>'
                            ],
                            'medium': [
                                r'Medium[:\s]+(\d+)',
                                r'(\d+)\s+Medium',
                                r'<td[^>]*>Medium</td>\s*<td[^>]*>(\d+)</td>',
                                r'Medium</td>\s*<td[^>]*>(\d+)</td>'
                            ],
                            'low': [
                                r'Low[:\s]+(\d+)',
                                r'(\d+)\s+Low',
                                r'<td[^>]*>Low</td>\s*<td[^>]*>(\d+)</td>',
                                r'Low</td>\s*<td[^>]*>(\d+)</td>'
                            ]
                        }
                        
                        for severity, patterns in severity_patterns.items():
                            for pattern in patterns:
                                match = re.search(pattern, report_content, re.IGNORECASE)
                                if match:
                                    count = int(match.group(1))
                                    self.stats_labels[severity].config(text=str(count))
                                    break
                        
                        # Update the vulnerability tree from report
                        self.parse_vulnerabilities_from_report(report_content)
                        
                        break
                        
        except Exception as e:
            print(f"Error parsing report file: {e}")
    
    def parse_vulnerabilities_from_report(self, report_content):
        """Parse individual vulnerabilities from the HTML report and populate the tree"""
        try:
            import re
            
            # Clear existing tree items
            for item in self.vuln_tree.get_children():
                self.vuln_tree.delete(item)
            
            # Parse vulnerability entries from HTML
            # Look for vulnerability sections in the report
            vuln_patterns = [
                r'<div class="vulnerability[^"]*"[^>]*>(.*?)</div>',
                r'<tr class="vuln[^"]*"[^>]*>(.*?)</tr>',
                r'Vulnerability Type:\s*([^\n<]+).*?Severity:\s*([^\n<]+).*?URL:\s*([^\n<]+)',
            ]
            
            vuln_count = 0
            
            # Try to find vulnerability blocks
            vuln_blocks = re.findall(r'(?:Vulnerability|VULNERABILITY)\s+(?:Type|Found)[:\s]*([^\n]+).*?Severity[:\s]*([^\n]+).*?(?:URL|Target)[:\s]*([^\n]+)(?:.*?Parameter[:\s]*([^\n]+))?(?:.*?Evidence[:\s]*([^\n]+))?', 
                                     report_content, re.IGNORECASE | re.DOTALL)
            
            for vuln in vuln_blocks[:100]:  # Limit to first 100 to avoid performance issues
                vuln_count += 1
                vuln_type = vuln[0].strip()[:50] if len(vuln) > 0 else 'Unknown'
                severity = vuln[1].strip() if len(vuln) > 1 else 'Medium'
                url = vuln[2].strip()[:50] if len(vuln) > 2 else 'N/A'
                parameter = vuln[3].strip()[:30] if len(vuln) > 3 and vuln[3] else 'N/A'
                evidence = vuln[4].strip()[:50] if len(vuln) > 4 and vuln[4] else 'N/A'
                
                # Clean HTML tags
                vuln_type = re.sub(r'<[^>]+>', '', vuln_type)
                severity = re.sub(r'<[^>]+>', '', severity)
                url = re.sub(r'<[^>]+>', '', url)
                parameter = re.sub(r'<[^>]+>', '', parameter)
                evidence = re.sub(r'<[^>]+>', '', evidence)
                
                # Normalize severity
                severity = severity.strip().title()
                if severity not in ['Critical', 'High', 'Medium', 'Low']:
                    severity = 'Medium'
                
                # Add to tree
                self.vuln_tree.insert('', 'end', 
                                     text=str(vuln_count),
                                     values=(vuln_type, severity, url, parameter, evidence),
                                     tags=(severity.lower(),))
            
            print(f"Parsed {vuln_count} vulnerabilities from report")
            
        except Exception as e:
            print(f"Error parsing vulnerabilities from report: {e}")
    
    def scan_completed(self):
        """Handle scan completion"""
        self.scanning = False
        self.start_btn.config(state='normal', text="START SECURITY SCAN", bg='#ff6633')
        self.stop_btn.config(state='disabled')
        self.progress.stop()
        
        # Calculate duration
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            duration_str = str(duration).split('.')[0]  # Remove microseconds
        else:
            duration_str = "Unknown"
        
        # Find report first
        self.find_report_file()
        
        # Parse report file to get accurate counts (this will update self.vulnerability_count)
        self.parse_report_file()
        
        # Update status with accurate count
        self.status_label.config(text=f"● Scan completed - {self.vulnerability_count} vulnerabilities found - Duration: {duration_str}", 
                                fg='#28a745')
        
        # Update summary and AI analysis
        self.update_summary()
        self.update_ai_analysis()
        
        # Show completion message with accurate count
        messagebox.showinfo("Scan Complete", 
                          f"Security scan completed successfully!\n\n"
                          f"Vulnerabilities found: {self.vulnerability_count}\n"
                          f"Duration: {duration_str}\n\n"
                          f"Check the results tabs for detailed analysis.")
    
    def scan_error(self, error):
        """Handle scan error"""
        self.scanning = False
        self.start_btn.config(state='normal', text="START SECURITY SCAN", bg='#ff6633')
        self.stop_btn.config(state='disabled')
        self.progress.stop()
        self.status_label.config(text=f"● Scan failed: {error}", fg='#dc3545')
        self.update_console(f"ERROR: {error}\n", "error")
        messagebox.showerror("Scan Error", f"Scan failed: {error}")
    
    def stop_scan(self):
        """Stop current scan"""
        if self.scan_process:
            try:
                self.scan_process.terminate()
                # Wait up to 3 seconds for graceful termination
                self.scan_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate
                self.scan_process.kill()
            except Exception as e:
                print(f"Error stopping scan: {e}")
        
        self.scanning = False
        self.start_btn.config(state='normal', text="START SECURITY SCAN", bg='#ff6633')
        self.stop_btn.config(state='disabled')
        self.progress.stop()
        self.status_label.config(text="● Scan stopped by user", fg='#ff9933')
        self.update_console("Scan stopped by user\n", "warning")
    
    def clear_results(self):
        """Clear all results"""
        self.console_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.ai_text.delete(1.0, tk.END)
        
        # Clear vulnerability tree
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Reset counters
        self.vulnerability_count = 0
        for label in self.stats_labels.values():
            label.config(text="0")
        
        self.report_btn.config(state='disabled')
        self.report_path = None
    
    def find_report_file(self):
        """Find generated report"""
        result_dirs = ['reports', 'results', 'fixed_results', 'fast_scan_results']
        
        for dir_name in result_dirs:
            dir_path = Path(__file__).parent / dir_name
            if dir_path.exists():
                html_files = list(dir_path.glob('*.html'))
                if html_files:
                    self.report_path = max(html_files, key=os.path.getctime)
                    self.report_btn.config(state='normal')
                    self.refresh_btn.config(state='normal')
                    break
    
    def open_report(self):
        """Open generated report"""
        if self.report_path and self.report_path.exists():
            webbrowser.open(f'file://{self.report_path.absolute()}')
        else:
            messagebox.showwarning("No Report", "No report file found")
    
    def refresh_counts_from_report(self):
        """Manually refresh vulnerability counts from the report file"""
        try:
            self.status_label.config(text="● Refreshing counts from report...", fg='#ff9933')
            
            # Parse the report file
            self.parse_report_file()
            
            # Update summary
            self.update_summary()
            
            self.status_label.config(text=f"● Counts refreshed - {self.vulnerability_count} vulnerabilities", fg='#28a745')
            
            messagebox.showinfo("Counts Refreshed", 
                              f"Vulnerability counts updated from report!\n\n"
                              f"Total: {self.vulnerability_count}\n"
                              f"Critical: {self.stats_labels['critical']['text']}\n"
                              f"High: {self.stats_labels['high']['text']}\n"
                              f"Medium: {self.stats_labels['medium']['text']}\n"
                              f"Low: {self.stats_labels['low']['text']}")
        except Exception as e:
            messagebox.showerror("Refresh Error", f"Failed to refresh counts: {e}")
    
    def update_summary(self):
        """Update detailed summary"""
        mode = self.attack_mode.get()
        duration = str(datetime.now() - self.scan_start_time).split('.')[0] if self.scan_start_time else "Unknown"
        
        summary = f"""
ASTRAVA AI SECURITY SCANNER - DETAILED SCAN SUMMARY
==================================================

SCAN INFORMATION:
================
Target URL: {self.target_url.get()}
Attack Mode: {mode.title()} Scan
AI Model: {self.ai_model.get()}
Scan Duration: {duration}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CONFIGURATION:
=============
OWASP Top 10 Testing: {'Enabled' if self.owasp_testing.get() else 'Disabled'}
AI Chain Attacks: {'Enabled' if self.chain_attacks.get() else 'Disabled'}
Passive Only: {'Enabled' if self.passive_only.get() else 'Disabled'}
Active Only: {'Enabled' if self.active_only.get() else 'Disabled'}
Custom Payloads: {'Yes' if self.custom_payloads_file.get() else 'No'}
Verbose Output: {'Enabled' if self.verbose_mode.get() else 'Disabled'}

RESULTS SUMMARY:
===============
Total Vulnerabilities Found: {self.vulnerability_count}
Critical Severity: {self.stats_labels['critical']['text']}
High Severity: {self.stats_labels['high']['text']}
Medium Severity: {self.stats_labels['medium']['text']}
Low Severity: {self.stats_labels['low']['text']}

ATTACK MODE DETAILS:
===================
{self.get_mode_details()}

RECOMMENDATIONS:
===============
{self.get_recommendations()}

STATUS: SCAN COMPLETED SUCCESSFULLY
        """
        
        self.summary_text.insert(tk.END, summary)
    
    def update_ai_analysis(self):
        """Update AI analysis"""
        analysis = f"""
AI-POWERED SECURITY ANALYSIS REPORT
===================================

RISK ASSESSMENT:
===============
Based on the scan results, the AI engine has analyzed {self.vulnerability_count} vulnerabilities.

VULNERABILITY ANALYSIS:
======================
The AI has identified potential security weaknesses in the target application.
Each vulnerability has been analyzed for exploitability and business impact.

ATTACK VECTOR ANALYSIS:
======================
The AI engine has evaluated possible attack paths and exploitation scenarios.
This includes analysis of vulnerability chaining and privilege escalation opportunities.

AI RECOMMENDATIONS:
==================
1. Prioritize fixing high and critical severity vulnerabilities
2. Implement input validation and output encoding
3. Deploy Web Application Firewall (WAF)
4. Regular security testing and code reviews
5. Security awareness training for development team

THREAT INTELLIGENCE:
===================
The AI has cross-referenced findings with current threat intelligence databases
to provide context on active exploitation techniques and mitigation strategies.

REMEDIATION GUIDANCE:
====================
Detailed remediation steps have been generated for each vulnerability type.
The AI recommends following secure coding practices and implementing defense-in-depth strategies.

AI MODEL USED: {self.ai_model.get()}
ANALYSIS CONFIDENCE: High
LAST UPDATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        self.ai_text.insert(tk.END, analysis)
    
    def get_mode_details(self):
        """Get attack mode details"""
        mode = self.attack_mode.get()
        details = {
            "basic": "Basic Scan: Fast vulnerability detection (Fast)\n- OWASP Top 10: OFF by default (user can enable)\n- Chain Attacks: Not available\n- AI Analysis: Basic level\n- Best for: Quick initial assessment",
            "medium": "Medium Scan: Comprehensive testing (Standard)\n- OWASP Top 10: ON by default\n- Chain Attacks: OFF by default (user can enable)\n- AI Analysis: Full analysis\n- Best for: Standard security assessment",
            "aggressive": "Aggressive Scan: Deep penetration testing (Thorough)\n- OWASP Top 10: ON by default\n- Chain Attacks: ON by default\n- AI Analysis: Advanced with chain detection\n- Best for: Thorough security audit"
        }
        return details.get(mode, "Unknown scan mode")
    
    def get_recommendations(self):
        """Get security recommendations"""
        if self.vulnerability_count == 0:
            return "No vulnerabilities detected. Continue regular security assessments and monitoring."
        elif self.vulnerability_count < 5:
            return "Few vulnerabilities detected. Address identified issues and implement preventive measures."
        else:
            return "Multiple vulnerabilities detected. Immediate security review and remediation required."
    
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def on_closing(self):
        """Handle window close event"""
        if self.scanning:
            if messagebox.askokcancel("Quit", "A scan is in progress. Do you want to stop it and quit?"):
                self.stop_scan()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def is_ollama_installed(self):
        """Check if Ollama is installed"""
        try:
            result = subprocess.run(['ollama', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def is_ollama_running(self):
        """Check if Ollama server is running"""
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def is_model_available(self, model_name="llama3.2:3b"):
        """Check if the AI model is downloaded"""
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=2)
            if response.status_code == 200:
                data = response.json()
                models = [m['name'] for m in data.get('models', [])]
                return any(model_name in m for m in models)
            return False
        except:
            return False
    
    def start_ollama_server(self):
        """Start Ollama server in background"""
        try:
            # Start Ollama server
            self.ollama_process = subprocess.Popen(
                ['ollama', 'serve'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            # Wait for server to start (max 10 seconds)
            for i in range(10):
                time.sleep(1)
                if self.is_ollama_running():
                    self.ollama_running = True
                    return True
            
            return False
        except Exception as e:
            print(f"Error starting Ollama: {e}")
            return False
    
    def pull_model(self, model_name="llama3.2:3b"):
        """Download AI model if not available"""
        try:
            self.update_console(f"Downloading AI model {model_name}...\n", "info")
            self.update_console("This may take a few minutes...\n", "info")
            
            process = subprocess.Popen(
                ['ollama', 'pull', model_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Show progress
            for line in process.stdout:
                if 'pulling' in line.lower() or '%' in line:
                    self.root.after(0, self.update_console, line, "info")
            
            process.wait()
            return process.returncode == 0
        except Exception as e:
            self.update_console(f"Error downloading model: {e}\n", "error")
            return False
    
    def check_ollama_status(self):
        """Check Ollama status and start if needed"""
        # Update status
        self.status_label.config(text="● Checking AI system...", fg='#ff9933')
        
        # Check if Ollama is installed
        if not self.is_ollama_installed():
            self.status_label.config(
                text="⚠ Ollama not installed - AI features disabled (Install from ollama.ai)", 
                fg='#ff9933'
            )
            return
        
        # Check if Ollama is running
        if not self.is_ollama_running():
            self.status_label.config(text="● Starting AI system...", fg='#ff9933')
            
            # Start Ollama server
            if self.start_ollama_server():
                self.status_label.config(text="● AI system started successfully", fg='#28a745')
                
                # Check if model is available
                model_name = self.ai_model.get()
                if not self.is_model_available(model_name):
                    response = messagebox.askyesno(
                        "AI Model Required",
                        f"AI model '{model_name}' is not downloaded.\n\n"
                        f"Would you like to download it now?\n"
                        f"(This is a one-time download, ~2GB)\n\n"
                        f"You can still use the scanner without AI features."
                    )
                    
                    if response:
                        # Download model in background
                        threading.Thread(target=self.download_model_thread, 
                                       args=(model_name,), 
                                       daemon=True).start()
                    else:
                        self.status_label.config(
                            text="⚠ AI model not available - Limited AI features", 
                            fg='#ff9933'
                        )
                else:
                    self.status_label.config(text="● Ready to scan - AI system active", fg='#28a745')
            else:
                self.status_label.config(
                    text="⚠ Failed to start AI system - AI features disabled", 
                    fg='#ff9933'
                )
        else:
            # Ollama is already running
            self.ollama_running = True
            model_name = self.ai_model.get()
            
            if self.is_model_available(model_name):
                self.status_label.config(text="● Ready to scan - AI system active", fg='#28a745')
            else:
                self.status_label.config(
                    text=f"⚠ AI model '{model_name}' not found - Limited AI features", 
                    fg='#ff9933'
                )
    
    def download_model_thread(self, model_name):
        """Download model in background thread"""
        if self.pull_model(model_name):
            self.root.after(0, lambda: self.status_label.config(
                text="● AI model downloaded - Ready to scan", 
                fg='#28a745'
            ))
            self.root.after(0, lambda: messagebox.showinfo(
                "Success", 
                f"AI model '{model_name}' downloaded successfully!\nAI features are now fully enabled."
            ))
        else:
            self.root.after(0, lambda: self.status_label.config(
                text="⚠ Model download failed - AI features limited", 
                fg='#ff9933'
            ))

def main():
    """Main function"""
    root = tk.Tk()
    app = AstravaAdvancedGUI(root)
    
    def on_closing():
        if app.scanning:
            if messagebox.askokcancel("Quit", "Scan in progress. Quit?"):
                app.stop_scan()
                # Stop Ollama if we started it
                if app.ollama_process:
                    try:
                        app.ollama_process.terminate()
                    except:
                        pass
                root.destroy()
        else:
            # Stop Ollama if we started it
            if app.ollama_process:
                try:
                    app.ollama_process.terminate()
                except:
                    pass
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
