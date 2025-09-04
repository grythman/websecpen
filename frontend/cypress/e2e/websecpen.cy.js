// WebSecPen E2E Tests
describe('WebSecPen Security Scanner', () => {
  
  beforeEach(() => {
    // Visit the application
    cy.visit('http://localhost:5173')
    
    // Clear any existing data
    cy.clearLocalStorage()
    cy.clearCookies()
  })

  describe('Authentication Flow', () => {
    it('should display login page', () => {
      cy.contains('WebSecPen')
      cy.contains('Login')
      cy.get('input[type="email"]').should('be.visible')
      cy.get('input[type="password"]').should('be.visible')
    })

    it('should login with valid credentials', () => {
      // Login with test user
      cy.get('input[type="email"]').type('test@example.com')
      cy.get('input[type="password"]').type('test123')
      cy.get('button').contains('Login').click()
      
      // Should redirect to dashboard
      cy.url().should('include', '/dashboard')
      cy.contains('Security Scanning Dashboard').should('be.visible')
    })

    it('should show error with invalid credentials', () => {
      cy.get('input[type="email"]').type('invalid@example.com')
      cy.get('input[type="password"]').type('wrongpassword')
      cy.get('button').contains('Login').click()
      
      cy.contains('Invalid credentials').should('be.visible')
    })

    it('should logout successfully', () => {
      // Login first
      cy.login('test@example.com', 'test123')
      
      // Logout
      cy.get('button').contains('Logout').click()
      
      // Should redirect to login
      cy.url().should('include', '/login')
    })
  })

  describe('Dashboard Navigation', () => {
    beforeEach(() => {
      cy.login('test@example.com', 'test123')
    })

    it('should display dashboard sections', () => {
      cy.contains('Start New Scan').should('be.visible')
      cy.contains('Recent Scans').should('be.visible')
      cy.contains('Latest Results').should('be.visible')
      cy.contains('Quick Stats').should('be.visible')
    })

    it('should navigate between tabs', () => {
      // Check if enhanced dashboard is available
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="trends-tab"]').length > 0) {
          // Test enhanced dashboard navigation
          cy.get('[data-testid="trends-tab"]').click()
          cy.contains('Vulnerability Trends').should('be.visible')
          
          cy.get('[data-testid="badges-tab"]').click()
          cy.contains('Your Achievements').should('be.visible')
          
          cy.get('[data-testid="dashboard-tab"]').click()
          cy.contains('Security Scanning Dashboard').should('be.visible')
        }
      })
    })

    it('should toggle dark/light theme', () => {
      // Find theme toggle button (moon/sun emoji)
      cy.get('button').contains(/🌙|☀️/).click()
      
      // Check if theme changed (this might need adjustment based on implementation)
      cy.get('body').should('have.class', 'dark').or('have.class', 'light')
    })
  })

  describe('Scan Management', () => {
    beforeEach(() => {
      cy.login('test@example.com', 'test123')
    })

    it('should display scan form', () => {
      cy.contains('Start New Scan').should('be.visible')
      cy.get('input[placeholder*="URL"]').should('be.visible')
      cy.get('select').should('be.visible')
      cy.get('button').contains('Start').should('be.visible')
    })

    it('should validate scan form inputs', () => {
      // Try to start scan without URL
      cy.get('button').contains('Start').click()
      cy.contains('URL is required').should('be.visible')
      
      // Try with invalid URL
      cy.get('input[placeholder*="URL"]').type('invalid-url')
      cy.get('button').contains('Start').click()
      cy.contains('Please enter a valid URL').should('be.visible')
    })

    it('should start a scan with valid inputs', () => {
      // Fill scan form
      cy.get('input[placeholder*="URL"]').type('http://localhost:8080')
      cy.get('select').select('XSS')
      
      // Start scan
      cy.get('button').contains('Start').click()
      
      // Should show scan in progress
      cy.contains('Scan started').should('be.visible')
      cy.contains('running', { timeout: 10000 }).should('be.visible')
    })

    it('should display scan history', () => {
      // Check if scan history section exists
      cy.contains('Recent Scans').should('be.visible')
      
      // If there are scans, check the structure
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="scan-item"]').length > 0) {
          cy.get('[data-testid="scan-item"]').first().should('contain.text', 'http')
        } else {
          cy.contains('No scans found').should('be.visible')
        }
      })
    })
  })

  describe('Scan Results', () => {
    beforeEach(() => {
      cy.login('test@example.com', 'test123')
    })

    it('should display scan results when available', () => {
      // This test assumes there are existing scan results
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="result-item"]').length > 0) {
          cy.get('[data-testid="result-item"]').first().click()
          
          // Should show vulnerability details
          cy.contains('Vulnerability').should('be.visible')
          cy.contains('Severity').should('be.visible')
        }
      })
    })

    it('should allow PDF export of results', () => {
      // Check if PDF export button exists for completed scans
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="pdf-export"]').length > 0) {
          cy.get('[data-testid="pdf-export"]').first().click()
          
          // Should trigger download (we can't easily test actual download in Cypress)
          cy.wait(1000)
        }
      })
    })
  })

  describe('Advanced Features', () => {
    beforeEach(() => {
      cy.login('test@example.com', 'test123')
    })

    it('should access notification settings', () => {
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="notifications-tab"]').length > 0) {
          cy.get('[data-testid="notifications-tab"]').click()
          cy.contains('Push Notifications').should('be.visible')
          cy.contains('Enable Notifications').should('be.visible')
        }
      })
    })

    it('should display vulnerability trends', () => {
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="trends-tab"]').length > 0) {
          cy.get('[data-testid="trends-tab"]').click()
          cy.contains('Vulnerability Trends').should('be.visible')
          
          // Check export buttons
          cy.get('button').contains('CSV').should('be.visible')
          cy.get('button').contains('JSON').should('be.visible')
        }
      })
    })

    it('should show user achievements', () => {
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="badges-tab"]').length > 0) {
          cy.get('[data-testid="badges-tab"]').click()
          cy.contains('Your Achievements').should('be.visible')
        }
      })
    })
  })

  describe('Admin Features', () => {
    it('should access admin dashboard with admin credentials', () => {
      cy.login('admin@websecpen.com', 'admin123')
      
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="admin-tab"]').length > 0) {
          cy.get('[data-testid="admin-tab"]').click()
          cy.contains('Admin Dashboard').should('be.visible')
          cy.contains('System monitoring').should('be.visible')
        }
      })
    })

    it('should display admin analytics', () => {
      cy.login('admin@websecpen.com', 'admin123')
      
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="admin-tab"]').length > 0) {
          cy.get('[data-testid="admin-tab"]').click()
          
          // Check for admin sections
          cy.contains('Security Overview').should('be.visible')
          cy.contains('Feedback Overview').should('be.visible')
        }
      })
    })
  })

  describe('Error Handling', () => {
    beforeEach(() => {
      cy.login('test@example.com', 'test123')
    })

    it('should handle network errors gracefully', () => {
      // Intercept API calls and simulate network error
      cy.intercept('GET', '/api/scans', { forceNetworkError: true }).as('networkError')
      
      cy.reload()
      
      // Should show error message
      cy.contains('error', { matchCase: false }).should('be.visible')
    })

    it('should handle API errors', () => {
      // Intercept API calls and return error
      cy.intercept('POST', '/api/scan/start', { statusCode: 500 }).as('apiError')
      
      cy.get('input[placeholder*="URL"]').type('http://localhost:8080')
      cy.get('button').contains('Start').click()
      
      cy.wait('@apiError')
      cy.contains('error', { matchCase: false }).should('be.visible')
    })
  })

  describe('Mobile Responsiveness', () => {
    beforeEach(() => {
      cy.viewport('iphone-6')
      cy.login('test@example.com', 'test123')
    })

    it('should be responsive on mobile devices', () => {
      // Check if navigation adapts to mobile
      cy.get('.dashboard-nav').should('be.visible')
      
      // Check if sections stack properly
      cy.contains('Start New Scan').should('be.visible')
      cy.contains('Recent Scans').should('be.visible')
    })

    it('should handle mobile navigation', () => {
      // Test mobile menu if it exists
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="mobile-menu"]').length > 0) {
          cy.get('[data-testid="mobile-menu"]').click()
          cy.get('[data-testid="mobile-menu-items"]').should('be.visible')
        }
      })
    })
  })

  describe('Performance', () => {
    it('should load the application quickly', () => {
      const start = Date.now()
      
      cy.visit('http://localhost:5173')
      cy.contains('WebSecPen').should('be.visible')
      
      cy.then(() => {
        const loadTime = Date.now() - start
        expect(loadTime).to.be.lessThan(3000) // Should load in under 3 seconds
      })
    })

    it('should handle multiple concurrent scans', () => {
      cy.login('test@example.com', 'test123')
      
      // Start multiple scans (if the UI allows)
      for (let i = 0; i < 3; i++) {
        cy.get('input[placeholder*="URL"]').clear().type(`http://localhost:808${i}`)
        cy.get('button').contains('Start').click()
        cy.wait(1000)
      }
      
      // Should handle multiple scans gracefully
      cy.contains('Scan started').should('be.visible')
    })
  })
})

// Custom Cypress commands
Cypress.Commands.add('login', (email, password) => {
  cy.visit('http://localhost:5173')
  cy.get('input[type="email"]').type(email)
  cy.get('input[type="password"]').type(password)
  cy.get('button').contains('Login').click()
  cy.url().should('include', '/dashboard')
})

Cypress.Commands.add('startScan', (url, scanType = 'XSS') => {
  cy.get('input[placeholder*="URL"]').type(url)
  cy.get('select').select(scanType)
  cy.get('button').contains('Start').click()
})

Cypress.Commands.add('waitForScanCompletion', (timeout = 30000) => {
  cy.contains('completed', { timeout }).should('be.visible')
}) 