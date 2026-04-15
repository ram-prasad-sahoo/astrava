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
    
    def __init__(self, logger=None, model=None):
        self.logger = logger
        self.ollama_url = "http://localhost:11434"
        self.ollama_process = None
        
        # Get model from parameter, config, or default
        if model:
            self.required_model = model
        else:
            try:
                from utils import config_store
                config = config_store.load_config()
                self.required_model = config.get("active_model", "llama3.2:3b")
            except:
                self.required_model = "llama3.2:3b"
        
        # Model list caching
        self._model_cache = None
        self._cache_timestamp = 0
        self._cache_duration = 60  # Cache for 60 seconds
    
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
            
            # Clear model cache since service is restarting
            self.clear_model_cache()
            
            # Start Ollama serve in background
            if sys.platform == 'win32':
                # Windows - use START command to run in separate window
                subprocess.Popen(
                    'start /B ollama serve',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                # Linux/Mac
                self.ollama_process = subprocess.Popen(
                    ['ollama', 'serve'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            # Wait for service to start (max 10 seconds with better checks)
            self.log("Waiting for Ollama service to start...")
            for i in range(10):
                time.sleep(1)
                if self.is_ollama_running():
                    self.log("✓ Ollama service started successfully!")
                    # Give it one more second to fully initialize
                    time.sleep(1)
                    return True
                if i < 9:  # Don't show on last iteration
                    self.log(f"  Checking... ({i+1}/10)")
            
            self.log("Ollama service started but not responding after 10 seconds", "WARNING")
            self.log("Try running 'ollama serve' manually in a separate terminal", "INFO")
            return False
            
        except Exception as e:
            self.log(f"Failed to start Ollama service: {e}", "ERROR")
            self.log("Try running 'ollama serve' manually in a separate terminal", "INFO")
            return False
    
    def clear_model_cache(self):
        """Clear the model list cache"""
        self._model_cache = None
        self._cache_timestamp = 0
    
    def list_models(self, force_refresh=False):
        """
        Execute 'ollama list' and parse available models
        Caches results for 60 seconds to avoid repeated subprocess calls
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh model list
        
        Returns: List of model names (e.g., ["llama3.2:3b", "mistral"])
        """
        # Check if cache is valid
        current_time = time.time()
        cache_age = current_time - self._cache_timestamp
        
        if not force_refresh and self._model_cache is not None and cache_age < self._cache_duration:
            # Return cached result
            return self._model_cache
        
        # Fetch fresh model list
        try:
            result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                # Skip header line (first line) if present
                if len(lines) > 1:
                    lines = lines[1:]
                else:
                    # Only header or empty output
                    models = []
                    # Update cache
                    self._model_cache = models
                    self._cache_timestamp = current_time
                    return models
                
                models = []
                for line in lines:
                    parts = line.split()
                    if parts:
                        # First column is model name (handles both "llama3.2:3b" and "mistral")
                        models.append(parts[0])
                
                # Update cache
                self._model_cache = models
                self._cache_timestamp = current_time
                return models
            else:
                self.log("Failed to list models: ollama list returned non-zero exit code", "WARNING")
                # Don't cache failures
                return []
        except FileNotFoundError:
            self.log("Failed to list models: ollama command not found", "WARNING")
            return []
        except subprocess.TimeoutExpired:
            self.log("Failed to list models: ollama list command timed out", "WARNING")
            return []
        except Exception as e:
            self.log(f"Failed to list models: {e}", "WARNING")
            return []
    
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
            print("\n[!] Ollama not found. Install it from: https://ollama.ai/download")
            return (False, msg)
        
        self.log("Ollama is installed ✓")
        print("[+] Ollama is installed ✓")
        
        # Check if Ollama is running
        if not self.is_ollama_running():
            self.log("Ollama service is not running. Starting...")
            print("[*] Ollama service is not running. Starting...")
            if not self.start_ollama_service():
                msg = "Failed to start Ollama service. AI features will be disabled."
                self.log(msg, "WARNING")
                print(f"\n[!] {msg}")
                print("[*] Try running 'ollama serve' manually in a separate terminal")
                print("[*] Then run the scan again")
                return (False, msg)
        else:
            self.log("Ollama service is running ✓")
            print("[+] Ollama service is running ✓")
        
        # Wait a moment for service to be fully ready
        time.sleep(1)
        
        # Clear cache to force fresh model detection
        self.clear_model_cache()
        
        # Check if model is available
        if not self.is_model_available():
            self.log(f"Model {self.required_model} is not downloaded.")
            print(f"[*] Model {self.required_model} is not downloaded.")
            
            if auto_download:
                self.log("Downloading model automatically...")
                print(f"[*] Downloading {self.required_model}... (this may take a few minutes)")
                if self.download_model():
                    self.log("Model downloaded successfully ✓")
                    print(f"[+] Model {self.required_model} downloaded successfully ✓")
                    return (True, "Ollama initialized successfully with model download")
                else:
                    msg = "Failed to download model. AI features will be limited."
                    self.log(msg, "WARNING")
                    print(f"[!] {msg}")
                    return (False, msg)
            else:
                msg = f"Model {self.required_model} not found. Please run: ollama pull {self.required_model}"
                self.log(msg, "WARNING")
                print(f"[!] {msg}")
                return (False, msg)
        else:
            self.log(f"Model {self.required_model} is available ✓")
            print(f"[+] Model {self.required_model} is available ✓")
        
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
