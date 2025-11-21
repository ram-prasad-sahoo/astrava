#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Cleanup Utility
Removes temporary files, cache, and old reports
"""

import os
import shutil
from pathlib import Path

def cleanup_project():
    """Clean up temporary files and cache"""
    print("🧹 Astrava AI Scanner - Cleanup Utility")
    print("=" * 40)
    
    cleanup_items = [
        # Cache directories
        ("__pycache__", "Python cache files"),
        ("*.pyc", "Compiled Python files"),
        
        # Temporary files
        ("*.tmp", "Temporary files"),
        ("*.log", "Log files (optional)"),
        
        # Old reports (optional)
        # ("reports/*.html", "Old HTML reports"),
        # ("fixed_results/*.html", "Old fixed results"),
    ]
    
    removed_count = 0
    
    for pattern, description in cleanup_items:
        try:
            if pattern == "__pycache__":
                # Remove __pycache__ directories
                for pycache_dir in Path(".").rglob("__pycache__"):
                    if pycache_dir.is_dir():
                        shutil.rmtree(pycache_dir)
                        print(f"✅ Removed: {pycache_dir}")
                        removed_count += 1
            
            elif pattern.startswith("*."):
                # Remove files by extension
                extension = pattern[2:]  # Remove "*."
                for file_path in Path(".").rglob(f"*.{extension}"):
                    if file_path.is_file() and not file_path.name.startswith("requirements"):
                        file_path.unlink()
                        print(f"✅ Removed: {file_path}")
                        removed_count += 1
        
        except Exception as e:
            print(f"⚠️  Could not remove {pattern}: {e}")
    
    print(f"\n🎉 Cleanup complete! Removed {removed_count} items.")
    
    # Show current project size
    try:
        total_size = sum(f.stat().st_size for f in Path(".").rglob("*") if f.is_file())
        size_mb = total_size / (1024 * 1024)
        print(f"📊 Current project size: {size_mb:.2f} MB")
    except:
        pass

def cleanup_reports():
    """Clean up old report files (interactive)"""
    report_dirs = ["reports", "fixed_results", "fast_scan_results"]
    
    for report_dir in report_dirs:
        dir_path = Path(report_dir)
        if dir_path.exists():
            html_files = list(dir_path.glob("*.html"))
            if html_files:
                print(f"\n📁 Found {len(html_files)} reports in {report_dir}/")
                response = input("Delete old reports? (y/N): ").lower()
                if response == 'y':
                    for html_file in html_files:
                        html_file.unlink()
                        print(f"✅ Removed: {html_file}")

if __name__ == "__main__":
    cleanup_project()
    
    # Ask about reports
    print("\n" + "=" * 40)
    cleanup_reports()
    
    print("\n✨ Astrava AI Scanner is now clean and optimized!")
