"""
Model Manager Module

Central coordinator for AI model selection and inference routing.
Manages local Ollama models only.
"""

import time
import sys
import os
import json
from typing import Optional, Tuple, Dict, List

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import config_store
import ollama_manager

load_config = config_store.load_config
save_config = config_store.save_config
config_set_active_model = config_store.set_active_model
OllamaManager = ollama_manager.OllamaManager


class ModelManager:
    """Manages AI model selection and inference routing (Ollama only)"""

    def __init__(self, logger=None):
        self.logger = logger
        self.ollama_manager = OllamaManager(logger)
        self.ollama_models: List[str] = []
        self.active_identifier: str = "xploiter/pentester"

    def log(self, message: str, level: str = "INFO") -> None:
        if self.logger:
            if level == "ERROR":
                self.logger.error(message)
            elif level == "WARNING":
                self.logger.warning(message)
            else:
                self.logger.info(message)
        else:
            print(f"[{level}] {message}")

    def _detect_ollama_models(self) -> List[str]:
        models = self.ollama_manager.list_models()
        if models:
            self.log(f"Detected {len(models)} Ollama models")
        else:
            self.log("No Ollama models detected", "WARNING")
        return models

    def initialize(self) -> bool:
        try:
            # Ensure Ollama is running first
            if not self.ollama_manager.is_ollama_running():
                self.log("Ollama not running, attempting to start...", "WARNING")
                success, msg = self.ollama_manager.initialize(auto_download=False)
                if not success:
                    self.log(f"Failed to start Ollama: {msg}", "ERROR")
                    return False
            
            # Load config
            config = load_config()
            
            # Detect models with fresh cache
            self.ollama_models = self._detect_ollama_models()
            
            # Set active model from config or default
            self.active_identifier = config.get("active_model", "xploiter/pentester")
            
            self.log(f"Model Manager initialized: ollama - {self.active_identifier}")
            self.log(f"Available Ollama models: {len(self.ollama_models)}")
            
            return True
        except Exception as e:
            self.log(f"Failed to initialize Model Manager: {e}", "ERROR")
            return False

    def get_available_models(self) -> Dict[str, List[str]]:
        return {
            "ollama": self.ollama_models.copy(),
            "api": []
        }

    def set_active_model(self, mode: str, identifier: str) -> bool:
        try:
            if identifier not in self.ollama_models:
                self.log(f"Ollama model not found: {identifier}", "WARNING")
            self.active_identifier = identifier
            success = config_set_active_model("ollama", identifier)
            if success:
                self.log(f"Active model set: ollama - {identifier}")
            else:
                self.log("Failed to persist active model to config", "ERROR")
            return success
        except Exception as e:
            self.log(f"Error setting active model: {e}", "ERROR")
            return False

    def get_active_model(self) -> Tuple[str, str]:
        return ("ollama", self.active_identifier)

    def verify_model_availability(self, mode: str = None, identifier: str = None) -> Tuple[bool, str]:
        if identifier is None:
            identifier = self.active_identifier
        try:
            if not self.ollama_manager.is_ollama_running():
                return (False, "Ollama service is not running")
            if identifier not in self.ollama_models:
                return (False, f"Model '{identifier}' not found in Ollama")
            return (True, f"Ollama model '{identifier}' is available")
        except Exception as e:
            self.log(f"Error verifying model availability: {e}", "ERROR")
            return (False, f"Error: {str(e)}")

    def get_status_display(self) -> Dict[str, any]:
        is_available, message = self.verify_model_availability()
        formatted_message = f"✓ {message}" if is_available else f"✗ {message}"
        provider_running = self.ollama_manager.is_ollama_running()
        model_available = self.active_identifier in self.ollama_models
        return {
            "active_mode": "ollama",
            "active_identifier": self.active_identifier,
            "is_available": is_available,
            "status_message": formatted_message,
            "provider_running": provider_running,
            "model_available": model_available,
            "status_messages": [formatted_message]
        }

    def refresh_ollama_models(self) -> List[str]:
        self.ollama_models = self.ollama_manager.list_models(force_refresh=True)
        self.log(f"Refreshed Ollama models: {len(self.ollama_models)} found")
        return self.ollama_models.copy()

    def query(self, prompt: str, **kwargs) -> str:
        """Route inference request to Ollama."""
        try:
            self.log(f"Routing query to Ollama model: {self.active_identifier}")
            return self._query_ollama(prompt, **kwargs)
        except Exception as e:
            self.log(f"Error during query routing: {e}", "ERROR")
            return ""

    def _query_ollama(self, prompt: str, **kwargs) -> str:
        """Query Ollama with automatic startup, error handling, and streaming support."""
        import requests

        system_prompt = kwargs.get('system_prompt', '')
        temperature = kwargs.get('temperature', 0.7)
        use_streaming = kwargs.get('streaming', True)
        timeout = kwargs.get('timeout', 45)  # Increased default timeout to 45 seconds

        payload = {
            "model": self.active_identifier,
            "prompt": f"System: {system_prompt}\n\nUser: {prompt}" if system_prompt else prompt,
            "stream": use_streaming,
            "options": {
                "temperature": temperature,
                "top_p": kwargs.get('top_p', 0.9),
                "top_k": kwargs.get('top_k', 40),
                "num_predict": kwargs.get('max_tokens', 150),  # Reduced from 256 to 150
                "num_ctx": 2048
            }
        }

        if "qwen3" in self.active_identifier.lower():
            payload["think"] = False

        try:
            response = requests.post(
                f"{self.ollama_manager.ollama_url}/api/generate",
                json=payload,
                timeout=timeout,
                stream=use_streaming
            )

            if response.status_code == 200:
                if use_streaming:
                    full_response = ""
                    full_thinking = ""
                    for line in response.iter_lines():
                        if line:
                            try:
                                chunk = json.loads(line.decode('utf-8'))
                                if 'response' in chunk:
                                    full_response += chunk['response']
                                if 'thinking' in chunk:
                                    full_thinking += chunk.get('thinking', '')
                                if chunk.get('done', False):
                                    break
                            except json.JSONDecodeError:
                                continue
                    return full_response.strip() or full_thinking.strip()
                else:
                    result = response.json()
                    text = result.get('response', '').strip()
                    if not text:
                        text = result.get('thinking', '').strip()
                    return text
            else:
                self.log(f"Ollama API error: HTTP {response.status_code} - {response.text[:200]}", "ERROR")
                return ""

        except requests.exceptions.ConnectionError:
            self.log("Ollama service not reachable - attempting to auto-start", "WARNING")
            try:
                success, msg = self.ollama_manager.initialize(auto_download=True)
                if success:
                    self.log("Ollama started successfully, retrying request", "INFO")
                    try:
                        response = requests.post(
                            f"{self.ollama_manager.ollama_url}/api/generate",
                            json=payload,
                            timeout=timeout,
                            stream=use_streaming
                        )
                        if response.status_code == 200:
                            if use_streaming:
                                full_response = ""
                                for line in response.iter_lines():
                                    if line:
                                        try:
                                            chunk = json.loads(line.decode('utf-8'))
                                            if 'response' in chunk:
                                                full_response += chunk['response']
                                            if chunk.get('done', False):
                                                break
                                        except json.JSONDecodeError:
                                            continue
                                return full_response.strip()
                            else:
                                result = response.json()
                                text = result.get('response', '').strip()
                                if not text:
                                    text = result.get('thinking', '').strip()
                                return text
                        else:
                            self.log(f"Ollama retry failed: HTTP {response.status_code}", "ERROR")
                            return ""
                    except Exception as retry_e:
                        self.log(f"Ollama retry failed: {retry_e}", "ERROR")
                        return ""
                else:
                    self.log(f"Failed to auto-start Ollama: {msg}", "ERROR")
                    return ""
            except Exception as start_e:
                self.log(f"Error attempting to start Ollama: {start_e}", "ERROR")
                return ""

        except requests.exceptions.Timeout:
            self.log(f"Ollama request timed out after {timeout} seconds", "WARNING")
            return ""
        except Exception as e:
            self.log(f"Error calling Ollama API: {e}", "ERROR")
            return ""

    def is_ai_available(self) -> bool:
        """Check if Ollama is available with at least one model."""
        if self.ollama_models:
            try:
                import requests
                response = requests.get(f"{self.ollama_manager.ollama_url}/api/tags", timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
        return False


# Global instance (optional, for convenience)
_model_manager_instance: Optional[ModelManager] = None


def get_model_manager(logger=None) -> ModelManager:
    global _model_manager_instance
    if _model_manager_instance is None:
        _model_manager_instance = ModelManager(logger)
        _model_manager_instance.initialize()
    return _model_manager_instance
