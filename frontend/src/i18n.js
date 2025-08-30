// i18n.js - Internationalization Configuration for WebSecPen
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// Translation resources
const resources = {
  en: {
    translation: {
      // Navigation
      welcome: 'Welcome to WebSecPen',
      dashboard: 'Dashboard',
      scans: 'Scans',
      history: 'Scan History',
      feedback: 'Feedback',
      settings: 'Settings',
      logout: 'Logout',
      login: 'Login',
      register: 'Register',
      
      // Scanning
      scan_button: 'Start Scan',
      new_scan: 'New Security Scan',
      target_url: 'Target URL',
      scan_type: 'Scan Type',
      advanced_options: 'Advanced Options',
      scan_depth: 'Scan Depth',
      include_sql: 'Include SQL Injection Tests',
      include_xss: 'Include XSS Tests',
      include_csrf: 'Include CSRF Tests',
      aggressive_mode: 'Aggressive Mode',
      scan_progress: 'Scan Progress',
      scan_complete: 'Scan Complete',
      vulnerabilities_found: 'Vulnerabilities Found',
      
      // Results
      scan_results: 'Scan Results',
      vulnerability: 'Vulnerability',
      severity: 'Severity',
      description: 'Description',
      remediation: 'Remediation',
      risk_score: 'Risk Score',
      pages_scanned: 'Pages Scanned',
      requests_made: 'Requests Made',
      
      // Severity levels
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      informational: 'Informational',
      
      // Feedback
      feedback_placeholder: 'Share your thoughts, report bugs, or suggest features...',
      feedback_type: 'Feedback Type',
      feedback_types: {
        general: 'General',
        bug: 'Bug Report',
        feature: 'Feature Request',
        performance: 'Performance Issue'
      },
      submit_feedback: 'Submit Feedback',
      feedback_sent: 'Thank you for your feedback!',
      
      // Chat
      chat_support: 'Support Chat',
      chat_placeholder: 'Type your message...',
      send_message: 'Send',
      chat_connecting: 'Connecting to support...',
      chat_connected: 'Connected to support',
      chat_disconnected: 'Disconnected from support',
      online_support: 'Support team online',
      offline_support: 'Support team offline',
      
      // Forms
      email: 'Email',
      password: 'Password',
      name: 'Name',
      confirm_password: 'Confirm Password',
      required_field: 'This field is required',
      invalid_email: 'Please enter a valid email address',
      password_mismatch: 'Passwords do not match',
      
      // Actions
      submit: 'Submit',
      cancel: 'Cancel',
      save: 'Save',
      delete: 'Delete',
      edit: 'Edit',
      view: 'View',
      download: 'Download',
      export: 'Export',
      refresh: 'Refresh',
      
      // Status
      loading: 'Loading...',
      error: 'Error',
      success: 'Success',
      warning: 'Warning',
      pending: 'Pending',
      running: 'Running',
      completed: 'Completed',
      failed: 'Failed',
      
      // Analytics
      total_scans: 'Total Scans',
      active_users: 'Active Users',
      recent_activity: 'Recent Activity',
      performance_metrics: 'Performance Metrics',
      system_health: 'System Health',
      
      // User roles
      free_user: 'Free User',
      premium_user: 'Premium User',
      admin_user: 'Administrator',
      upgrade_to_premium: 'Upgrade to Premium',
      scan_limit_reached: 'Scan limit reached. Upgrade to premium for unlimited scans.',
      
      // API
      api_documentation: 'API Documentation',
      api_key: 'API Key',
      generate_api_key: 'Generate API Key',
      api_key_generated: 'API key generated successfully',
      copy_api_key: 'Copy API Key',
      
      // Errors
      network_error: 'Network error. Please check your connection.',
      unauthorized: 'You are not authorized to perform this action.',
      scan_failed: 'Scan failed. Please try again.',
      invalid_url: 'Please enter a valid URL.',
      
      // Time
      seconds_ago: '{{count}} seconds ago',
      minutes_ago: '{{count}} minutes ago',
      hours_ago: '{{count}} hours ago',
      days_ago: '{{count}} days ago',
      
      // Onboarding
      onboarding: {
        welcome_title: 'Welcome to WebSecPen!',
        welcome_content: 'Let us show you around our AI-powered security platform.',
        dashboard_title: 'Your Dashboard',
        dashboard_content: 'This is your command center for monitoring scans and analytics.',
        scan_title: 'Start a Scan',
        scan_content: 'Click here to begin scanning websites for vulnerabilities.',
        results_title: 'View Results',
        results_content: 'Access detailed vulnerability reports and AI analysis.',
        feedback_title: 'Give Feedback',
        feedback_content: 'Help us improve by sharing your thoughts and suggestions.',
        chat_title: 'Get Support',
        chat_content: 'Chat with our support team for real-time assistance.',
        complete_title: 'You\'re All Set!',
        complete_content: 'Start scanning and discover security insights with AI.',
        next: 'Next',
        previous: 'Previous',
        skip: 'Skip Tour',
        finish: 'Finish'
      }
    }
  },
  mn: {
    translation: {
      // Navigation
      welcome: 'WebSecPen-д тавтай морил',
      dashboard: 'Хяналтын самбар',
      scans: 'Сканнууд',
      history: 'Скан түүх',
      feedback: 'Санал хүсэлт',
      settings: 'Тохиргоо',
      logout: 'Гарах',
      login: 'Нэвтрэх',
      register: 'Бүртгүүлэх',
      
      // Scanning
      scan_button: 'Скан эхлүүлэх',
      new_scan: 'Шинэ аюулгүй байдлын скан',
      target_url: 'Зорилтот URL',
      scan_type: 'Скан төрөл',
      advanced_options: 'Нарийвчилсан сонголтууд',
      scan_depth: 'Скан гүн',
      include_sql: 'SQL инжекшн тест оруулах',
      include_xss: 'XSS тест оруулах',
      include_csrf: 'CSRF тест оруулах',
      aggressive_mode: 'Хүчтэй горим',
      scan_progress: 'Скан явц',
      scan_complete: 'Скан дууссан',
      vulnerabilities_found: 'Олдсон эмзэг байдлууд',
      
      // Results
      scan_results: 'Скан үр дүн',
      vulnerability: 'Эмзэг байдал',
      severity: 'Ноцтой байдал',
      description: 'Тайлбар',
      remediation: 'Засварлах арга',
      risk_score: 'Эрсдэлийн оноо',
      pages_scanned: 'Скан хийсэн хуудас',
      requests_made: 'Хийсэн хүсэлт',
      
      // Severity levels
      critical: 'Маш ноцтой',
      high: 'Өндөр',
      medium: 'Дунд',
      low: 'Бага',
      informational: 'Мэдээллийн',
      
      // Feedback
      feedback_placeholder: 'Санал бодол, алдаа мэдээлэх эсвэл шинэ боломж санал болгох...',
      feedback_type: 'Санал хүсэлтийн төрөл',
      feedback_types: {
        general: 'Ерөнхий',
        bug: 'Алдаа мэдээлэх',
        feature: 'Шинэ боломж',
        performance: 'Гүйцэтгэлийн асуудал'
      },
      submit_feedback: 'Санал хүсэлт илгээх',
      feedback_sent: 'Санал хүсэлт илгээсэнд баярлалаа!',
      
      // Chat
      chat_support: 'Дэмжлэгийн чат',
      chat_placeholder: 'Мессежээ бичнэ үү...',
      send_message: 'Илгээх',
      chat_connecting: 'Дэмжлэгтэй холбогдож байна...',
      chat_connected: 'Дэмжлэгтэй холбогдсон',
      chat_disconnected: 'Дэмжлэгээс салсан',
      online_support: 'Дэмжлэгийн баг онлайн',
      offline_support: 'Дэмжлэгийн баг оффлайн',
      
      // Forms
      email: 'Имэйл',
      password: 'Нууц үг',
      name: 'Нэр',
      confirm_password: 'Нууц үг баталгаажуулах',
      required_field: 'Энэ талбар заавал шаардлагатай',
      invalid_email: 'Зөв имэйл хаяг оруулна уу',
      password_mismatch: 'Нууц үг таарахгүй байна',
      
      // Actions
      submit: 'Илгээх',
      cancel: 'Болих',
      save: 'Хадгалах',
      delete: 'Устгах',
      edit: 'Засах',
      view: 'Харах',
      download: 'Татах',
      export: 'Экспорт',
      refresh: 'Шинэчлэх',
      
      // Status
      loading: 'Ачааллаж байна...',
      error: 'Алдаа',
      success: 'Амжилттай',
      warning: 'Анхааруулга',
      pending: 'Хүлээгдэж байна',
      running: 'Ажиллаж байна',
      completed: 'Дууссан',
      failed: 'Амжилтгүй',
      
      // Analytics
      total_scans: 'Нийт скан',
      active_users: 'Идэвхтэй хэрэглэгчид',
      recent_activity: 'Сүүлийн үйлдэл',
      performance_metrics: 'Гүйцэтгэлийн хэмжүүр',
      system_health: 'Системийн эрүүл мэнд',
      
      // User roles
      free_user: 'Үнэгүй хэрэглэгч',
      premium_user: 'Премиум хэрэглэгч',
      admin_user: 'Администратор',
      upgrade_to_premium: 'Премиум болгон шинэчлэх',
      scan_limit_reached: 'Скан хязгаарт хүрсэн. Хязгааргүй скан хийхээр премиум болгон шинэчилнэ үү.',
      
      // API
      api_documentation: 'API баримт бичиг',
      api_key: 'API түлхүүр',
      generate_api_key: 'API түлхүүр үүсгэх',
      api_key_generated: 'API түлхүүр амжилттай үүссэн',
      copy_api_key: 'API түлхүүр хуулах',
      
      // Errors
      network_error: 'Сүлжээний алдаа. Холболтоо шалгана уу.',
      unauthorized: 'Энэ үйлдлийг хийх эрх танд байхгүй.',
      scan_failed: 'Скан амжилтгүй. Дахин оролдоно уу.',
      invalid_url: 'Зөв URL оруулна уу.',
      
      // Time
      seconds_ago: '{{count}} секундын өмнө',
      minutes_ago: '{{count}} минутын өмнө',
      hours_ago: '{{count}} цагийн өмнө',
      days_ago: '{{count}} өдрийн өмнө',
      
      // Onboarding
      onboarding: {
        welcome_title: 'WebSecPen-д тавтай морил!',
        welcome_content: 'Манай хиймэл оюунтай аюулгүй байдлын платформыг танилцуулъя.',
        dashboard_title: 'Таны хяналтын самбар',
        dashboard_content: 'Энэ бол скан болон шинжилгээг хянах таны удирдлагын төв.',
        scan_title: 'Скан эхлүүлэх',
        scan_content: 'Вэб сайтын эмзэг байдлыг скан хийхээр энд дарна уу.',
        results_title: 'Үр дүн харах',
        results_content: 'Дэлгэрэнгүй эмзэг байдлын тайлан болон хиймэл оюуны шинжилгээнд хандана уу.',
        feedback_title: 'Санал өгөх',
        feedback_content: 'Санал бодол, зөвлөмж өгөөд бидэнд сайжруулахад туслана уу.',
        chat_title: 'Дэмжлэг авах',
        chat_content: 'Бодит цагийн тусламжийн төлөө манай дэмжлэгийн багтай чатлана уу.',
        complete_title: 'Та бэлэн боллоо!',
        complete_content: 'Скан хийж эхэлж, хиймэл оюунтай аюулгүй байдлын мэдлэг олж авна уу.',
        next: 'Дараах',
        previous: 'Өмнөх',
        skip: 'Аялалыг алгасах',
        finish: 'Дуусгах'
      }
    }
  }
};

// Initialize i18n
i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    debug: process.env.NODE_ENV === 'development',
    
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      lookupLocalStorage: 'websecpen_language',
      caches: ['localStorage']
    },
    
    interpolation: {
      escapeValue: false // React already escapes values
    },
    
    react: {
      useSuspense: false // Disable suspense for better loading experience
    }
  });

export default i18n; 