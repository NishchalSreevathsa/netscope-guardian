#!/usr/bin/env python3
"""
NetScope Guardian Setup Script
Automated setup and installation for the Chrome extension and backend
"""

import os
import sys
import subprocess
import json
from pathlib import Path

class NetScopeSetup:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.backend_dir = self.project_root / "backend"
        
    def print_banner(self):
        """Print setup banner"""
        print("""
🛡️  NetScope Guardian Setup
=====================================
AI-Powered Browser Threat Contextualizer

🚀 Setting up your cybersecurity extension...
        """)
    
    def check_python_version(self):
        """Check if Python version is compatible"""
        print("📋 Checking Python version...")
        
        if sys.version_info < (3, 9):
            print("❌ Python 3.9 or higher is required!")
            print(f"   Current version: {sys.version}")
            return False
        
        print(f"✅ Python {sys.version.split()[0]} detected")
        return True
    
    def setup_backend(self):
        """Set up the Python backend"""
        print("\n🐍 Setting up Python backend...")
        
        # Create virtual environment
        venv_path = self.backend_dir / "venv"
        if not venv_path.exists():
            print("   Creating virtual environment...")
            subprocess.run([
                sys.executable, "-m", "venv", str(venv_path)
            ], check=True)
        
        # Determine activation script
        if sys.platform == "win32":
            pip_path = venv_path / "Scripts" / "pip"
            python_path = venv_path / "Scripts" / "python"
        else:
            pip_path = venv_path / "bin" / "pip"
            python_path = venv_path / "bin" / "python"
        
        # Install requirements
        print("   Installing dependencies...")
        subprocess.run([
            str(pip_path), "install", "-r", 
            str(self.backend_dir / "requirements.txt")
        ], check=True)
        
        # Create .env file if it doesn't exist
        env_file = self.backend_dir / ".env"
        if not env_file.exists():
            print("   Creating environment configuration...")
            api_key = input("\n🔑 Enter your Gemini API Key: ").strip()
            
            with open(env_file, "w") as f:
                f.write(f"GEMINI_API_KEY={api_key}\n")
                f.write("PORT=8000\n")
                f.write("HOST=127.0.0.1\n")
                f.write("DEBUG=false\n")
        
        print("✅ Backend setup complete!")
        return str(python_path)
    
    def create_extension_icons(self):
        """Create placeholder icons if they don't exist"""
        print("\n🎨 Setting up extension icons...")
        
        icons_dir = self.project_root / "icons"
        icons_dir.mkdir(exist_ok=True)
        
        # Create simple SVG icons if they don't exist
        icon_sizes = [16, 48, 128]
        
        for size in icon_sizes:
            icon_path = icons_dir / f"icon{size}.png"
            if not icon_path.exists():
                # Create a simple SVG and note that user should replace with proper icons
                svg_content = f'''
<svg width="{size}" height="{size}" xmlns="http://www.w3.org/2000/svg">
    <rect width="{size}" height="{size}" fill="#3b82f6"/>
    <text x="50%" y="50%" text-anchor="middle" dy="0.35em" 
          font-family="Arial" font-size="{size//2}" fill="white">🛡️</text>
</svg>
'''
                # Note: For production, convert SVG to PNG
                with open(icons_dir / f"icon{size}.svg", "w") as f:
                    f.write(svg_content.strip())
        
        print("   📝 Note: Replace SVG files with proper PNG icons for production")
        print("✅ Extension icons setup complete!")
    
    def test_backend(self, python_path):
        """Test the backend setup"""
        print("\n🧪 Testing backend configuration...")
        
        # Test if the backend can start
        test_script = """
import sys
sys.path.insert(0, 'backend')
try:
    from main import app
    print("✅ Backend imports successful")
except ImportError as e:
    print(f"❌ Backend import failed: {e}")
    sys.exit(1)
"""
        
        result = subprocess.run([
            python_path, "-c", test_script
        ], capture_output=True, text=True, cwd=str(self.project_root))
        
        if result.returncode == 0:
            print("✅ Backend test passed!")
            return True
        else:
            print(f"❌ Backend test failed: {result.stderr}")
            return False
    
    def generate_demo_script(self):
        """Generate demo script for YouTube video"""
        print("\n🎬 Generating demo script...")
        
        demo_script = """
# NetScope Guardian Demo Script
# =============================

## Pre-Demo Setup
1. Start the backend server:
   cd backend && python main.py

2. Ensure Chrome extension is loaded

## Demo Scenario 1: Threat Analysis
1. Visit a website with visible IP addresses (e.g., security blog)
2. Highlight an IP address (e.g., 8.8.8.8)
3. Right-click → "Analyze with NetScope Guardian"
4. Show the AI analysis and explanation
5. Demonstrate the threat scoring system

## Demo Scenario 2: Security Headers
1. Visit different websites (HTTP vs HTTPS)
2. Click extension popup → "Analyze Page"
3. Show security headers analysis
4. Demonstrate the Gemini AI explanations
5. Compare secure vs insecure sites

## Demo Scenario 3: Network Monitoring
1. Open the extension dashboard
2. Browse to a website with multiple resources
3. Show real-time network monitoring
4. Demonstrate suspicious activity detection

## Key Features to Highlight
- Real-time AI analysis with Gemini 2.0
- Educational explanations for beginners
- Professional interface for experts
- Privacy-first approach (local processing)
- Comprehensive threat intelligence

## Technical Highlights
- Chrome Manifest V3 compliance
- Modern JavaScript and Python backend
- RESTful API with FastAPI
- Responsive dark theme UI
- Secure by design architecture

## Wrap-up Points
- Industry-relevant cybersecurity tool
- Educational value for learning
- Open source and extensible
- Production-ready architecture
"""
        
        with open(self.project_root / "DEMO_SCRIPT.md", "w") as f:
            f.write(demo_script.strip())
        
        print("✅ Demo script created: DEMO_SCRIPT.md")
    
    def print_completion_message(self, python_path):
        """Print completion message with next steps"""
        print(f"""
🎉 NetScope Guardian Setup Complete!
=====================================

✅ Backend configured and tested
✅ Extension files ready
✅ Demo script generated

🚀 Next Steps:

1. Start the Backend Server:
   cd backend
   {python_path} main.py

2. Install Chrome Extension:
   • Open Chrome → chrome://extensions/
   • Enable "Developer mode"
   • Click "Load unpacked"
   • Select the netscope-guardian folder

3. Test the Extension:
   • Click the extension icon in Chrome
   • Try "Analyze Current Page"
   • Right-click any IP/domain and analyze

4. Create Your Demo Video:
   • Follow the script in DEMO_SCRIPT.md
   • Record using OBS Studio or similar
   • Upload to YouTube and share the link

📚 Documentation: README.md
🔧 API Docs: http://localhost:8000/docs (when backend running)
🎬 Demo Script: DEMO_SCRIPT.md

Happy threat hunting! 🛡️
        """)
    
    def run(self):
        """Run the complete setup process"""
        self.print_banner()
        
        # Check prerequisites
        if not self.check_python_version():
            return False
        
        try:
            # Setup components
            python_path = self.setup_backend()
            self.create_extension_icons()
            
            # Test setup
            if not self.test_backend(python_path):
                print("❌ Setup completed with errors.