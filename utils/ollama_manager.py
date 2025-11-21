"""
Ollama Manager - Automatically manages Ollama service and models
"""

import subprocess
import time
import requests
import sys
import os
from pathlib import Path


class OllamaManager:
    """Manages Ollama service and models automatically"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.ollama_url = "http://localhost:11434"
        self.ollama_process = None
        self.required_model = "llama3.2:3b"
    
    def log(self, message, level="INFO"):
        """Log message"""
        if self.logger:
            if level == "ERROR":
                self.logger.error(message)
            elif level == "WARNING":
                self.logger.warning(message)
            else:
                self.logger.info(message)
        else:
            print(f"[{level}] {message}")
    
    def is_ollama_installed(self):
        """Check if Ollama is installed"""
        try:
            result = subprocess.run(
                ['ollama', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def is_ollama_running(self):
        """Check if Ollama service is running"""
        try:
            response = requests.get(f'{self.ollama_url}/api/tags', timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def start_ollama_service(self):
        """Start Ollama service in background"""
        try:
            self.log("Starting Ollama service...")
            
            # Start Ollama serve in background
            if sys.platform == 'win32':
                # Windows
                self.ollama_process = subprocess.Popen(
                    ['ollama', 'serve'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                # Linux/Mac
                self.ollama_process = subprocess.Popen(
                    ['ollama', 'serve'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            # Wait for service to start (max 15 seconds)
            for i in range(15):
                time.sleep(1)
                if self.is_ollama_running():
                    self.log("Ollama service started successfully!")
                    return True
                if i % 3 == 0:
                    self.log(f"Waiting for Ollama service to start... ({i+1}/15)")
            
            self.log("Ollama service started but not responding", "WARNING")
            return False
            
        except Exception as e:
            self.log(f"Failed to start Ollama service: {e}", "ERROR")
            return False
    
    def is_model_available(self, model_name=None):
        """Check if the required model is downloaded"""
        if model_name is None:
            model_name = self.required_model
        
        try:
            response = requests.get(f'{self.ollama_url}/api/tags', timeout=2)
            if response.status_code == 200:
                data = response.json()
                models = [m['name'] for m in data.get('models', [])]
                # Check if model exists (with or without tag)
                return any(model_name.split(':')[0] in m for m in models)
            return False
        except:
            return False
    
    def download_model(self, model_name=None):
        """Download the required model"""
        if model_name is None:
            model_name = self.required_model
        
        try:
            self.log(f"Downloading AI model: {model_name}")
            self.log("This may take a few minutes (one-time download)...")
            
            # Run ollama pull
            process = subprocess.Popen(
                ['ollama', 'pull', model_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Show progress
            for line in process.stdout:
                if 'pulling' in line.lower() or '%' in line or 'success' in line.lower():
                    print(f"    {line.strip()}")
            
            process.wait()
            
            if process.returncode == 0:
                self.log(f"Model {model_name} downloaded successfully!")
                return True
            else:
                self.log(f"Failed to download model {model_name}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error downloading model: {e}", "ERROR")
            return False
    
    def initialize(self, auto_download=True):
        """
        Initialize Ollama - check installation, start service, download model
        Returns: (success, message)
        """
        # Check if Ollama is installed
        if not self.is_ollama_installed():
            msg = "Ollama is not installed. AI features will be disabled."
            self.log(msg, "WARNING")
            self.log("Install from: https://ollama.ai/download", "INFO")
            return (False, msg)
        
        self.log("Ollama is installed ✓")
        
        # Check if Ollama is running
        if not self.is_ollama_running():
            self.log("Ollama service is not running. Starting...")
            if not self.start_ollama_service():
                msg = "Failed to start Ollama service. AI features will be disabled."
                self.log(msg, "WARNING")
                return (False, msg)
        else:
            self.log("Ollama service is running ✓")
        
        # Check if model is available
        if not self.is_model_available():
            self.log(f"Model {self.required_model} is not downloaded.")
            
            if auto_download:
                self.log("Downloading model automatically...")
                if self.download_model():
                    self.log("Model downloaded successfully ✓")
                    return (True, "Ollama initialized successfully with model download")
                else:
                    msg = "Failed to download model. AI features will be limited."
                    self.log(msg, "WARNING")
                    return (False, msg)
            else:
                msg = f"Model {self.required_model} not found. Please run: ollama pull {self.required_model}"
                self.log(msg, "WARNING")
                return (False, msg)
        else:
            self.log(f"Model {self.required_model} is available ✓")
        
        return (True, "Ollama initialized successfully")
    
    def stop_service(self):
        """Stop Ollama service if we started it"""
        if self.ollama_process:
            try:
                self.ollama_process.terminate()
                self.ollama_process.wait(timeout=5)
                self.log("Ollama service stopped")
            except:
                try:
                    self.ollama_process.kill()
                except:
                    pass


def quick_check():
    """Quick check and initialization of Ollama"""
    manager = OllamaManager()
    success, message = manager.initialize(auto_download=True)
    return success, message


if __name__ == "__main__":
    # Test the manager
    print("Testing Ollama Manager...")
    manager = OllamaManager()
    success, message = manager.initialize(auto_download=True)
    print(f"\nResult: {message}")
    print(f"Success: {success}")
