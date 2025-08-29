# 🛡️ WebSecPen - AI-Powered Security Scanner

<div align="center">
  <img src="frontend/public/logo.svg" alt="WebSecPen Logo" width="200"/>
  
  **Advanced Web Application Security Scanner with AI-Powered Analysis**
  
  [![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
  [![React](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org/)
  [![Flask](https://img.shields.io/badge/Flask-2.3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
  [![AI Powered](https://img.shields.io/badge/AI-HuggingFace-yellow.svg)](https://huggingface.co/)
</div>

## 🌟 Features

### 🔍 **Advanced Security Scanning**
- **Real Vulnerability Detection**: XSS, SQL Injection, CSRF, Directory Traversal
- **Custom Python Scanner**: Purpose-built security scanner with multi-threading
- **Live Progress Monitoring**: Real-time scan status updates with progress indicators
- **Comprehensive Reporting**: Detailed vulnerability analysis with severity ratings

### 🤖 **AI-Powered Analysis**
- **HuggingFace NLP Integration**: BART, RoBERTa, and DistilBERT models
- **Intelligent Summarization**: AI-generated vulnerability summaries in plain English
- **Risk Assessment**: Automated severity analysis and confidence scoring
- **Executive Reporting**: Management-ready security summaries
- **Smart Recommendations**: Actionable remediation steps powered by AI

### 🎨 **Professional User Experience**
- **Modern React Frontend**: Responsive design with dark/light theme support
- **Mobile-First Design**: Optimized for all devices and screen sizes
- **Enhanced Error Handling**: Beautiful notifications with auto-dismiss
- **Loading States**: Smart progress indicators and loading spinners
- **Professional Branding**: Custom logo with animated scanner beam effects

### 🔐 **Enterprise Security**
- **JWT Authentication**: Secure session management with automatic expiry
- **Role-Based Access**: Admin and user permission levels
- **Session Validation**: Client-side token verification and auto-logout
- **Secure API Design**: CORS-enabled with standardized error responses

### 📊 **Data Management**
- **SQLAlchemy ORM**: Robust database layer with PostgreSQL/SQLite support
- **Scan History**: Persistent storage of all security assessments
- **User Management**: Complete user registration and profile management
- **Result Analytics**: Comprehensive scan statistics and reporting

## 🚀 Quick Start

### Prerequisites

- **Node.js** (v16+) and **npm**
- **Python** (3.8+) and **pip**
- **PostgreSQL** (production) or **SQLite** (development)

### 🏗️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/websecpen.git
   cd websecpen
   ```

2. **Backend Setup**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Environment Configuration**
   ```bash
   # Create .env file in backend/
   FLASK_ENV=development
   JWT_SECRET_KEY=your-super-secure-secret-key-here
   DATABASE_URL=sqlite:///websecpen.db
   # For production: postgresql://user:pass@host:port/dbname
   ```

4. **Database Initialization**
   ```bash
   flask db upgrade
   python app.py  # Creates default admin user
   ```

5. **Frontend Setup**
   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```

### 🎯 First Launch

1. **Start Backend** (Terminal 1):
   ```bash
   cd backend && source venv/bin/activate && python app.py
   ```

2. **Start Frontend** (Terminal 2):
   ```bash
   cd frontend && npm run dev
   ```

3. **Launch Vulnerable Target** (Terminal 3):
   ```bash
   cd backend && python dummy_target.py
   ```

4. **Access Application**:
   - **Frontend**: http://localhost:5173 (or 5174)
   - **Backend API**: http://localhost:5000
   - **Vulnerable Target**: http://localhost:8080

## 🔑 Default Credentials

```bash
# Admin User
Email: admin@websecpen.com
Password: admin123

# Regular User  
Email: test@example.com
Password: test123
```

## 📖 Usage Guide

### 🔍 **Running Your First Scan**

1. **Login** to the dashboard using default credentials
2. **Start New Scan**:
   - Enter target URL (e.g., `http://localhost:8080`)
   - Select scan type (XSS, SQLi, CSRF, Directory, or Comprehensive)
   - Click "Start Security Scan"
3. **Monitor Progress** in real-time with live updates
4. **View Results** with AI-powered analysis and recommendations
5. **Export Reports** in PDF format (coming soon)

### 🤖 **AI Analysis Features**

The AI analysis provides:
- **Executive Summary**: High-level security overview for management
- **Technical Analysis**: Detailed vulnerability breakdown for developers  
- **Risk Assessment**: Automated severity scoring with confidence levels
- **Smart Recommendations**: Actionable steps to fix identified issues
- **Trend Analysis**: Pattern recognition across multiple scans

### 📊 **Dashboard Overview**

- **Start New Scan**: Initiate security assessments
- **Recent Scans**: View scan history with filtering and sorting
- **Latest Results**: Preview recent findings with AI insights
- **Quick Stats**: Overview of total scans and risk distribution

## 🏗️ Architecture

### **Frontend (React)**
```
src/
├── components/          # Reusable UI components
│   ├── Login.jsx       # Authentication interface
│   ├── Dashboard.jsx   # Main application dashboard  
│   ├── ScanForm.jsx    # Security scan configuration
│   ├── ScanHistory.jsx # Historical scan results
│   ├── ResultPreview.jsx # Vulnerability result display
│   ├── Logo.jsx        # Animated brand logo
│   └── ErrorDisplay.jsx # Global error notifications
├── context/            # React Context providers
│   ├── ThemeContext.jsx # Dark/light theme management
│   └── ErrorContext.jsx # Global error state
├── utils/              # Utility functions
│   └── api.js          # Centralized API service
└── assets/             # Static assets and styling
```

### **Backend (Flask)**
```
backend/
├── app.py              # Main Flask application & API routes
├── models.py           # SQLAlchemy database models
├── scanner.py          # Custom security scanner engine
├── nlp_service.py      # HuggingFace AI integration
├── dummy_target.py     # Vulnerable test application
└── requirements.txt    # Python dependencies
```

### **Key Components**

- **🔍 Custom Scanner**: Multi-threaded Python scanner for real vulnerability detection
- **🤖 AI Service**: HuggingFace models for intelligent analysis and reporting
- **🔐 JWT Auth**: Secure authentication with automatic session management
- **📱 Responsive UI**: Mobile-first design with professional branding
- **🎨 Theme System**: Dark/light mode with CSS custom properties

## 🛠️ Development

### **Adding New Scan Types**

1. **Update Scanner Engine** (`backend/scanner.py`):
   ```python
   def _scan_new_vulnerability(self, target_url):
       # Implement detection logic
       pass
   ```

2. **Add to Frontend** (`frontend/src/components/ScanForm.jsx`):
   ```javascript
   const scanTypes = [
     // Add new scan type option
     { value: 'NewVuln', label: 'New Vulnerability', description: '...' }
   ];
   ```

### **Customizing AI Analysis**

Modify `backend/nlp_service.py` to:
- Add new HuggingFace models
- Customize analysis prompts
- Enhance recommendation generation
- Add industry-specific insights

### **Extending the UI**

- **Components**: All React components support theming and responsive design
- **Styling**: CSS custom properties in `src/index.css` for consistent theming
- **Icons**: Emoji-based icons for accessibility and cross-platform support

## 🚀 Deployment

### **Production Backend (Render/Heroku)**

1. **Environment Variables**:
   ```bash
   FLASK_ENV=production
   JWT_SECRET_KEY=production-secret-key
   DATABASE_URL=postgresql://user:pass@host:port/dbname
   ```

2. **Deploy Commands**:
   ```bash
   # Build: pip install -r requirements.txt
   # Start: gunicorn --bind 0.0.0.0:$PORT app:app
   ```

### **Production Frontend (Vercel/Netlify)**

1. **Build Configuration**:
   ```bash
   npm run build
   # Build output: dist/
   ```

2. **Environment Variables**:
   ```bash
   REACT_APP_API_URL=https://your-backend.onrender.com
   ```

### **Docker Deployment**

```bash
# Backend
docker build -t websecpen-backend ./backend
docker run -p 5000:5000 websecpen-backend

# Frontend  
docker build -t websecpen-frontend ./frontend
docker run -p 3000:3000 websecpen-frontend
```

## 🧪 Testing

### **Backend Tests**
```bash
cd backend
python -m pytest tests/
```

### **Frontend Tests**
```bash
cd frontend
npm test
```

### **E2E Tests (Cypress)**
```bash
cd frontend
npx cypress open
```

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** changes: `git commit -m 'Add amazing feature'`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **HuggingFace** for providing state-of-the-art NLP models
- **React Team** for the excellent frontend framework
- **Flask Community** for the lightweight Python web framework
- **Security Community** for vulnerability detection methodologies

## 📞 Support

- **Documentation**: [Wiki](https://github.com/your-org/websecpen/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-org/websecpen/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/websecpen/discussions)

---

<div align="center">
  <strong>Built with ❤️ for the security community</strong>
  <br />
  <em>Empowering developers to build more secure applications</em>
</div> 