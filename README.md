# WebSecPen - Web Security Penetration Testing Tool

A modern web application for automated security scanning and vulnerability assessment.

## 🚀 Features Implemented (Tasks 5-12)

### Frontend (React + Vite)
- ✅ **Task 5**: Login/Auth UI with comprehensive validation and responsive design
- ✅ **Task 6**: Dashboard Layout with navigation, grid system, and component integration
- ✅ **Task 7**: Scan Form with advanced input validation and API integration
- ✅ **Task 8**: Scan History with sorting, filtering, and rich data display
- ✅ **Task 9**: Result Preview with detailed vulnerability visualization
- ✅ **Task 10**: Dark/Light Mode Toggle with persistent theme storage

### Backend (Flask API)
- ✅ **Task 11**: `/scan/start` endpoint with comprehensive validation
- ✅ **Task 12**: `/scan/result/<id>` endpoint with detailed mock data
- ✅ **Bonus**: Additional endpoints for status checking and scan management

## 🛠️ Setup Instructions

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The backend will run on `http://localhost:5000`

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

The frontend will run on `http://localhost:5173`

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/scan/start` | Start a new security scan |
| GET | `/scan/result/<id>` | Get scan results |
| GET | `/scan/status/<id>` | Get scan status |
| GET | `/scans` | Get all scans |

### Example API Usage

**Start a scan:**
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","scan_type":"XSS"}' \
  http://localhost:5000/scan/start
```

**Get scan results:**
```bash
curl http://localhost:5000/scan/result/1
```

## 🎨 UI Components

### 1. Login Component (`/src/components/Login.jsx`)
- Email/password validation
- Loading states and error handling
- Responsive design for mobile/desktop
- Theme support

### 2. Dashboard Component (`/src/components/Dashboard.jsx`)
- Grid-based layout
- Navigation bar with theme toggle
- Integration of all major components
- Quick stats overview

### 3. Scan Form Component (`/src/components/ScanForm.jsx`)
- URL validation with regex
- Multiple scan types (XSS, SQLi, CSRF, Directory)
- Real-time API integration
- Success/error feedback

### 4. Scan History Component (`/src/components/ScanHistory.jsx`)
- Sortable columns
- Status and type filtering
- Responsive table design
- Action buttons for viewing/downloading

### 5. Result Preview Component (`/src/components/ResultPreview.jsx`)
- Vulnerability severity visualization
- Summary statistics
- Detailed finding cards
- Export options

## 🌓 Theme System

The application supports light and dark themes with:
- CSS custom properties for consistent theming
- localStorage persistence
- Smooth transitions
- Component-level theme awareness

## 📱 Responsive Design

All components are fully responsive with:
- Mobile-first design approach
- Flexible grid layouts
- Touch-friendly interfaces
- Optimized typography scaling

## 🔐 Security Features

- Input validation and sanitization
- XSS protection
- CORS configuration
- Error handling and logging

## 🧪 Testing

**Backend API Test:**
```bash
# Health check
curl http://localhost:5000/health

# Start scan
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","scan_type":"XSS"}' \
  http://localhost:5000/scan/start
```

**Frontend Test:**
1. Open `http://localhost:5173`
2. Use demo credentials to login
3. Navigate through dashboard components
4. Test theme toggle functionality
5. Try starting a scan and viewing results

## 📂 Project Structure

```
websecpen/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Login.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ScanForm.jsx
│   │   │   ├── ScanHistory.jsx
│   │   │   └── ResultPreview.jsx
│   │   ├── App.jsx
│   │   ├── ThemeContext.jsx
│   │   └── index.css
│   └── package.json
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   ├── test_nlp.py
│   └── test_zap.py
└── README.md
```

## 🚧 Next Steps (Tasks 13-25)

The foundation is now complete for:
- Database integration (SQLite/PostgreSQL)
- JWT authentication
- OWASP ZAP integration
- HuggingFace NLP analysis
- PDF report generation
- Advanced dashboard features

## 🎯 Demo Credentials

For testing the login interface:
- Email: any valid email format
- Password: minimum 6 characters

## 💡 Features Highlights

- **Modern UI/UX**: Clean, professional design with smooth animations
- **Full Responsiveness**: Works seamlessly on desktop, tablet, and mobile
- **Theme Support**: Light/dark mode with system preference detection
- **API Integration**: Real-time communication between frontend and backend
- **Error Handling**: Comprehensive validation and user feedback
- **Accessibility**: WCAG-compliant design patterns

The application is now ready for the next phase of development and integration with real security scanning tools. 