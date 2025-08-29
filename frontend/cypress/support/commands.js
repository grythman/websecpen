// cypress/support/commands.js - Custom Cypress Commands for WebSecPen

// ***********************************************
// Custom commands for WebSecPen Security Scanner
// ***********************************************

// Login command
Cypress.Commands.add('loginViaUI', (email = 'test@example.com', password = 'test123') => {
  cy.visit('/')
  cy.get('body').then(($body) => {
    if ($body.find('.login-container').length > 0) {
      cy.get('input[type="email"]').type(email)
      cy.get('input[type="password"]').type(password)
      cy.get('button[type="submit"]').click()
      cy.get('.dashboard', { timeout: 10000 }).should('be.visible')
    }
  })
})

// API-based login for faster test setup
Cypress.Commands.add('loginViaAPI', (email = 'test@example.com', password = 'test123') => {
  cy.request({
    method: 'POST',
    url: `${Cypress.env('apiUrl')}/auth/login`,
    body: { email, password },
    failOnStatusCode: false
  }).then((response) => {
    if (response.status === 200) {
      window.localStorage.setItem('authToken', response.body.access_token)
      window.localStorage.setItem('isAuthenticated', 'true')
    }
  })
})

// Start a security scan
Cypress.Commands.add('startScan', (url = 'http://localhost:8080', scanType = 'XSS') => {
  cy.get('input[type="url"]').clear().type(url)
  cy.get('select').select(scanType)
  cy.get('button[type="submit"]').contains('Start Security Scan').click()
})

// Wait for scan completion
Cypress.Commands.add('waitForScanCompletion', (scanId, timeout = 30000) => {
  cy.window().then((win) => {
    const token = win.localStorage.getItem('authToken')
    
    const checkScanStatus = () => {
      return cy.request({
        method: 'GET',
        url: `${Cypress.env('apiUrl')}/scan/status/${scanId}`,
        headers: { Authorization: `Bearer ${token}` },
        failOnStatusCode: false
      }).then((response) => {
        if (response.body.status === 'completed') {
          return true
        } else if (response.body.status === 'failed') {
          throw new Error('Scan failed')
        }
        return false
      })
    }
    
    cy.waitUntil(checkScanStatus, { timeout, interval: 2000 })
  })
})

// Check for notification with specific type
Cypress.Commands.add('checkNotification', (type = 'success', message = null) => {
  cy.get(`.${type}-notification`, { timeout: 10000 }).should('be.visible')
  if (message) {
    cy.get(`.${type}-notification`).should('contain', message)
  }
})

// Clear all notifications
Cypress.Commands.add('clearNotifications', () => {
  cy.get('.notification-close').each(($btn) => {
    cy.wrap($btn).click()
  })
})

// Take a full page screenshot with timestamp
Cypress.Commands.add('screenshotWithTimestamp', (name) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  cy.screenshot(`${name}-${timestamp}`)
})

// Wait for loading spinners to disappear
Cypress.Commands.add('waitForLoading', () => {
  cy.get('.loading-spinner', { timeout: 1000 }).should('not.exist')
})

// Verify responsive design at different breakpoints
Cypress.Commands.add('checkResponsive', () => {
  const viewports = [
    { width: 375, height: 667, name: 'mobile' },
    { width: 768, height: 1024, name: 'tablet' },
    { width: 1440, height: 900, name: 'desktop' }
  ]
  
  viewports.forEach((viewport) => {
    cy.viewport(viewport.width, viewport.height)
    cy.get('.dashboard-nav').should('be.visible')
    cy.get('.logo-container').should('be.visible')
    cy.screenshotWithTimestamp(`responsive-${viewport.name}`)
  })
})

// Custom assertion for theme checking
Cypress.Commands.add('shouldHaveTheme', (theme) => {
  cy.get('.dashboard').should('have.class', theme)
  cy.get('body').should('have.attr', 'data-theme', theme)
})

// API health check
Cypress.Commands.add('checkAPIHealth', () => {
  cy.request({
    method: 'GET',
    url: `${Cypress.env('apiUrl')}/health`,
    timeout: 10000
  }).then((response) => {
    expect(response.status).to.eq(200)
    expect(response.body).to.have.property('status', 'healthy')
  })
})

// Intercept and mock API responses
Cypress.Commands.add('mockScanResponse', (scanId = '123', status = 'completed') => {
  cy.intercept('POST', '**/scan/start', {
    statusCode: 200,
    body: { scan_id: scanId, status: 'started' }
  }).as('startScan')
  
  cy.intercept('GET', `**/scan/status/${scanId}`, {
    statusCode: 200,
    body: { 
      status,
      progress_percentage: 100,
      vulnerabilities_found: 3
    }
  }).as('scanStatus')
  
  cy.intercept('GET', `**/scan/result/${scanId}`, {
    statusCode: 200,
    body: {
      scan_id: scanId,
      target_url: 'http://localhost:8080',
      status: 'completed',
      vulnerabilities_count: 3,
      vulnerabilities: [
        {
          name: 'Reflected XSS',
          risk_level: 'High',
          description: 'Test vulnerability'
        }
      ]
    }
  }).as('scanResults')
})

// ***********************************************
// Accessibility Testing Commands
// ***********************************************

// Tab navigation test
Cypress.Commands.add('testTabNavigation', () => {
  cy.get('body').tab()
  cy.focused().should('be.visible')
  
  // Continue tabbing through interactive elements
  let tabCount = 0
  const maxTabs = 20 // Prevent infinite loops
  
  const tabThrough = () => {
    if (tabCount < maxTabs) {
      cy.focused().then(($el) => {
        if ($el.length) {
          cy.focused().tab()
          tabCount++
          tabThrough()
        }
      })
    }
  }
  
  tabThrough()
})

// Check for ARIA attributes
Cypress.Commands.add('checkAccessibility', () => {
  // Check for essential ARIA attributes
  cy.get('button').each(($btn) => {
    cy.wrap($btn).should('have.attr', 'type')
  })
  
  cy.get('input').each(($input) => {
    cy.wrap($input).should('have.attr', 'type')
  })
  
  cy.get('form').should('have.attr', 'aria-label')
})

// ***********************************************
// Performance Testing Commands  
// ***********************************************

// Measure page load performance
Cypress.Commands.add('measurePerformance', () => {
  cy.window().then((win) => {
    cy.wrap(win.performance.timing).should('have.property', 'loadEventEnd')
    
    const loadTime = win.performance.timing.loadEventEnd - win.performance.timing.navigationStart
    cy.log(`Page load time: ${loadTime}ms`)
    
    // Assert reasonable load time (adjust threshold as needed)
    expect(loadTime).to.be.lessThan(5000) // 5 seconds
  })
}) 