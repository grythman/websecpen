```mermaid
classDiagram
    class User {
        +int id
        +string email
        +string password
        +string role
        +datetime created_at
        +login()
        +logout()
        +register()
        +update()
    }
    
    class Scan {
        +int id
        +int user_id
        +string url
        +string status
        +json results
        +datetime created_at
        +start()
        +get_status()
        +get_results()
        +cancel()
    }
    
    class Vulnerability {
        +int id
        +int scan_id
        +string type
        +string severity
        +string description
        +string recommendation
        +classify()
        +get_cvss()
        +get_fix()
    }
    
    class ZAPScanner {
        +ZAPv2 zap
        +string proxy_url
        +spider_scan()
        +active_scan()
        +get_alerts()
        +get_status()
    }
    
    class AIAdvisor {
        +string model
        +string api_key
        +analyze()
        +recommend()
        +risk_assess()
    }
    
    class ReportGenerator {
        +json scan_data
        +string template
        +generate_pdf()
        +export_json()
        +export_csv()
    }
    
    User ||--o{ Scan : creates
    Scan ||--o{ Vulnerability : contains
    ZAPScanner ..> Scan : scans
    AIAdvisor ..> Vulnerability : analyzes
    ReportGenerator ..> Scan : generates
```
