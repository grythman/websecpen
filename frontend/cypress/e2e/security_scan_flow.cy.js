// cypress/e2e/security_scan_flow.cy.js - E2E Tests for WebSecPen
describe('WebSecPen Security Scanner E2E Tests', () => {
  
  beforeEach(() => {
    // Visit the application
    cy.visit('/')
    
    // Wait for the application to load
    cy.get('[data-testid="login-container"], [data-testid="dashboard-container"]', { timeout: 10000 })
      .should('be.visible')
  })

  describe('Authentication Flow', () => {
    
    it('should display login page with logo and branding', () => {
      // Check if we're on login page
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          // Verify logo is displayed
          cy.get('.logo-container').should('be.visible')
          
          // Verify login form elements
          cy.get('input[type="email"]').should('be.visible')
          cy.get('input[type="password"]').should('be.visible')
          cy.get('button[type="submit"]').should('be.visible')
          
          // Verify branding text
          cy.contains('Sign in to your security scanning dashboard').should('be.visible')
        }
      })
    })

    it('should login with valid credentials', () => {
      // Skip if already logged in
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          // Perform login
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          
          // Wait for redirect to dashboard
          cy.url({ timeout: 10000 }).should('not.include', '/login')
          cy.get('.dashboard').should('be.visible')
        }
      })
    })

    it('should show error for invalid credentials', () => {
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          // Try invalid login
          cy.get('input[type="email"]').type('invalid@test.com')
          cy.get('input[type="password"]').type('wrongpassword')
          cy.get('button[type="submit"]').click()
          
          // Check for error notification
          cy.get('.error-notification', { timeout: 5000 }).should('be.visible')
        }
      })
    })
  })

  describe('Dashboard Functionality', () => {
    
    beforeEach(() => {
      // Ensure we're logged in for dashboard tests
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
        }
      })
    })

    it('should display dashboard with all sections', () => {
      // Verify main dashboard elements
      cy.get('.dashboard-nav').should('be.visible')
      cy.get('.logo-container').should('be.visible')
      cy.get('.dashboard-main').should('be.visible')
      
      // Verify dashboard sections
      cy.contains('Start New Scan').should('be.visible')
      cy.contains('Recent Scans').should('be.visible')
      cy.contains('Latest Results').should('be.visible')
      cy.contains('Quick Stats').should('be.visible')
    })

    it('should toggle theme successfully', () => {
      // Find and click theme toggle
      cy.get('.theme-toggle').click()
      
      // Verify theme change (check for dark class)
      cy.get('.dashboard').should('have.class', 'dark')
      
      // Toggle back
      cy.get('.theme-toggle').click()
      cy.get('.dashboard').should('have.class', 'light')
    })
  })

  describe('Security Scanning Workflow', () => {
    
    beforeEach(() => {
      // Login and navigate to scan form
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
        }
      })
    })

    it('should start a security scan successfully', () => {
      // Fill out scan form
      cy.get('input[type="url"]').clear().type('http://localhost:8080')
      cy.get('select').select('XSS')
      
      // Submit scan
      cy.get('button[type="submit"]').contains('Start Security Scan').click()
      
      // Verify success notification
      cy.get('.success-notification', { timeout: 10000 }).should('be.visible')
      cy.get('.success-notification').should('contain', 'Scan started successfully')
      
      // Verify scan info is displayed
      cy.get('.scan-info', { timeout: 5000 }).should('be.visible')
      cy.get('.info-card').should('contain', 'Scan ID:')
    })

    it('should validate URL input', () => {
      // Try invalid URL
      cy.get('input[type="url"]').clear().type('not-a-url')
      cy.get('button[type="submit"]').click()
      
      // Check for validation error
      cy.get('.error-notification', { timeout: 5000 }).should('be.visible')
      cy.get('.error-notification').should('contain', 'valid URL')
    })

    it('should require URL and scan type', () => {
      // Try submitting empty form
      cy.get('input[type="url"]').clear()
      cy.get('button[type="submit"]').click()
      
      // Check for validation error
      cy.get('.error-notification', { timeout: 5000 }).should('be.visible')
    })

    it('should show loading state during scan submission', () => {
      // Fill form
      cy.get('input[type="url"]').clear().type('http://localhost:8080')
      cy.get('select').select('XSS')
      
      // Submit and check loading state
      cy.get('button[type="submit"]').click()
      cy.get('.loading-spinner', { timeout: 2000 }).should('be.visible')
      cy.get('button[type="submit"]').should('contain', 'Starting Scan')
    })
  })

  describe('Scan History and Results', () => {
    
    beforeEach(() => {
      // Login
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
        }
      })
    })

    it('should display scan history', () => {
      // Check if scan history section is visible
      cy.get('.history-section').should('be.visible')
      cy.contains('Recent Scans').should('be.visible')
    })

    it('should display result preview', () => {
      // Check if result preview section is visible
      cy.get('.result-section').should('be.visible')
      cy.contains('Latest Results').should('be.visible')
    })

    it('should show quick stats', () => {
      // Verify stats section
      cy.get('.stats-section').should('be.visible')
      cy.get('.stats-grid').should('be.visible')
      
      // Check for stat items
      cy.get('.stat-item').should('have.length.at.least', 3)
      cy.contains('Total Scans').should('be.visible')
    })
  })

  describe('Error Handling and Edge Cases', () => {
    
    beforeEach(() => {
      // Login
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
        }
      })
    })

    it('should handle network errors gracefully', () => {
      // Intercept and force network error
      cy.intercept('POST', '**/scan/start', { forceNetworkError: true }).as('networkError')
      
      // Try to start scan
      cy.get('input[type="url"]').clear().type('http://localhost:8080')
      cy.get('select').select('XSS')
      cy.get('button[type="submit"]').click()
      
      // Should show error notification
      cy.get('.error-notification', { timeout: 10000 }).should('be.visible')
    })

    it('should handle API errors', () => {
      // Intercept and return error
      cy.intercept('POST', '**/scan/start', { 
        statusCode: 500, 
        body: { error: 'Internal server error' } 
      }).as('serverError')
      
      // Try to start scan
      cy.get('input[type="url"]').clear().type('http://localhost:8080')
      cy.get('select').select('XSS')
      cy.get('button[type="submit"]').click()
      
      // Should show error notification
      cy.get('.error-notification', { timeout: 10000 }).should('be.visible')
    })
  })

  describe('Responsive Design', () => {
    
    const viewports = [
      { device: 'iphone-6', width: 375, height: 667 },
      { device: 'ipad-2', width: 768, height: 1024 },
      { device: 'macbook-15', width: 1440, height: 900 }
    ]

    viewports.forEach((viewport) => {
      it(`should be responsive on ${viewport.device}`, () => {
        cy.viewport(viewport.width, viewport.height)
        
        // Login if needed
        cy.get('body').then(($body) => {
          if ($body.find('[data-testid="login-container"]').length > 0) {
            cy.get('input[type="email"]').type('test@example.com')
            cy.get('input[type="password"]').type('test123')
            cy.get('button[type="submit"]').click()
            cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
          }
        })
        
        // Verify key elements are visible and properly sized
        cy.get('.dashboard-nav').should('be.visible')
        cy.get('.logo-container').should('be.visible')
        cy.get('.dashboard-main').should('be.visible')
        
        // Take screenshot for visual verification
        cy.screenshot(`responsive-${viewport.device}`)
      })
    })
  })

  describe('Accessibility', () => {
    
    beforeEach(() => {
      // Login
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
        }
      })
    })

    it('should support keyboard navigation', () => {
      // Test tab navigation
      cy.get('body').tab()
      cy.focused().should('be.visible')
      
      // Navigate through form elements
      cy.get('input[type="url"]').focus().should('be.focused')
      cy.get('input[type="url"]').tab()
      cy.focused().should('not.be', 'input[type="url"]')
    })

    it('should have proper ARIA labels', () => {
      // Check for ARIA labels on form elements
      cy.get('button[type="submit"]').should('have.attr', 'aria-busy')
      cy.get('form').should('have.attr', 'aria-label')
    })
  })

  describe('Logout Functionality', () => {
    
    beforeEach(() => {
      // Login
      cy.get('body').then(($body) => {
        if ($body.find('[data-testid="login-container"]').length > 0) {
          cy.get('input[type="email"]').type('test@example.com')
          cy.get('input[type="password"]').type('test123')
          cy.get('button[type="submit"]').click()
          cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
        }
      })
    })

    it('should logout successfully', () => {
      // Click logout button
      cy.get('.logout').click()
      
      // Should redirect to login page
      cy.get('[data-testid="login-container"]', { timeout: 5000 }).should('be.visible')
      
      // Verify we can't access dashboard without auth
      cy.visit('/')
      cy.get('[data-testid="login-container"]').should('be.visible')
    })
  })
})

// Custom commands for WebSecPen
Cypress.Commands.add('loginViaAPI', (email = 'test@example.com', password = 'test123') => {
  cy.request({
    method: 'POST',
    url: `${Cypress.env('apiUrl')}/auth/login`,
    body: { email, password }
  }).then((response) => {
    window.localStorage.setItem('authToken', response.body.access_token)
    window.localStorage.setItem('isAuthenticated', 'true')
  })
})

Cypress.Commands.add('startScanViaAPI', (url = 'http://localhost:8080', scanType = 'XSS') => {
  cy.window().then((win) => {
    const token = win.localStorage.getItem('authToken')
    cy.request({
      method: 'POST',
      url: `${Cypress.env('apiUrl')}/scan/start`,
      headers: { Authorization: `Bearer ${token}` },
      body: { url, scan_type: scanType }
    })
  })
}) 