// huggingfaceNLP.js - HuggingFace Inference API Integration
// This service allows the frontend to use HuggingFace NLP models via HTTP API

class HuggingFaceNLPService {
  constructor() {
    // HuggingFace Inference API endpoints
    this.baseURL = 'https://api-inference.huggingface.co/models';
    
    // Popular models for different NLP tasks
    this.models = {
      // Text Classification
      sentiment: 'cardiffnlp/twitter-roberta-base-sentiment-latest',
      emotion: 'j-hartmann/emotion-english-distilroberta-base',
      
      // Text Generation
      summarization: 'facebook/bart-large-cnn',
      textGeneration: 'gpt2',
      
      // Named Entity Recognition
      ner: 'dbmdz/bert-large-cased-finetuned-conll03-english',
      
      // Question Answering
      qa: 'deepset/roberta-base-squad2',
      
      // Vulnerability Analysis (custom models)
      securityAnalysis: 'microsoft/DialoGPT-medium',
      
      // Translation
      translation: 'Helsinki-NLP/opus-mt-en-zh'
    };
    
    // API key (should be set via environment variable)
    this.apiKey = process.env.REACT_APP_HUGGINGFACE_API_KEY || null;
  }

  /**
   * Make a request to HuggingFace Inference API
   */
  async makeRequest(model, inputs, options = {}) {
    const url = `${this.baseURL}/${model}`;
    
    const headers = {
      'Content-Type': 'application/json',
    };
    
    // Add API key if available
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    
    const payload = {
      inputs,
      ...options
    };
    
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        throw new Error(`HuggingFace API error: ${response.status} ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('HuggingFace API request failed:', error);
      throw error;
    }
  }

  /**
   * Analyze sentiment of text
   */
  async analyzeSentiment(text) {
    try {
      const result = await this.makeRequest(this.models.sentiment, text);
      
      // Process result to get sentiment
      if (Array.isArray(result) && result.length > 0) {
        const sentiment = result[0];
        return {
          label: sentiment.label,
          score: sentiment.score,
          confidence: Math.round(sentiment.score * 100)
        };
      }
      
      return { label: 'NEUTRAL', score: 0.5, confidence: 50 };
    } catch (error) {
      console.error('Sentiment analysis failed:', error);
      return { label: 'NEUTRAL', score: 0.5, confidence: 50, error: error.message };
    }
  }

  /**
   * Analyze emotions in text
   */
  async analyzeEmotion(text) {
    try {
      const result = await this.makeRequest(this.models.emotion, text);
      
      if (Array.isArray(result) && result.length > 0) {
        const emotions = result[0];
        return emotions.map(emotion => ({
          label: emotion.label,
          score: emotion.score,
          confidence: Math.round(emotion.score * 100)
        }));
      }
      
      return [{ label: 'neutral', score: 0.5, confidence: 50 }];
    } catch (error) {
      console.error('Emotion analysis failed:', error);
      return [{ label: 'neutral', score: 0.5, confidence: 50, error: error.message }];
    }
  }

  /**
   * Summarize text
   */
  async summarizeText(text, maxLength = 150) {
    try {
      const result = await this.makeRequest(
        this.models.summarization, 
        text,
        { parameters: { max_length: maxLength } }
      );
      
      if (Array.isArray(result) && result.length > 0) {
        return {
          summary: result[0].summary_text,
          original_length: text.length,
          summary_length: result[0].summary_text.length
        };
      }
      
      return { summary: text.substring(0, maxLength) + '...', original_length: text.length };
    } catch (error) {
      console.error('Text summarization failed:', error);
      return { summary: text.substring(0, maxLength) + '...', original_length: text.length, error: error.message };
    }
  }

  /**
   * Extract named entities from text
   */
  async extractEntities(text) {
    try {
      const result = await this.makeRequest(this.models.ner, text);
      
      if (Array.isArray(result) && result.length > 0) {
        return result[0].map(entity => ({
          word: entity.word,
          entity: entity.entity,
          score: entity.score,
          confidence: Math.round(entity.score * 100)
        }));
      }
      
      return [];
    } catch (error) {
      console.error('Entity extraction failed:', error);
      return [];
    }
  }

  /**
   * Analyze vulnerability descriptions for security insights
   */
  async analyzeVulnerability(vulnerabilityText) {
    try {
      // Use sentiment analysis to assess severity
      const sentiment = await this.analyzeSentiment(vulnerabilityText);
      
      // Use summarization to create concise description
      const summary = await this.summarizeText(vulnerabilityText, 100);
      
      // Extract entities to identify potential attack vectors
      const entities = await this.extractEntities(vulnerabilityText);
      
      // Determine risk level based on sentiment and keywords
      const riskKeywords = ['critical', 'high', 'severe', 'exploit', 'attack', 'vulnerability'];
      const hasRiskKeywords = riskKeywords.some(keyword => 
        vulnerabilityText.toLowerCase().includes(keyword)
      );
      
      let riskLevel = 'LOW';
      if (sentiment.label === 'NEGATIVE' && sentiment.score > 0.7) {
        riskLevel = 'HIGH';
      } else if (hasRiskKeywords || sentiment.score > 0.5) {
        riskLevel = 'MEDIUM';
      }
      
      return {
        riskLevel,
        sentiment,
        summary: summary.summary,
        entities,
        confidence: Math.round((sentiment.score + (hasRiskKeywords ? 0.3 : 0)) * 100),
        recommendations: this.generateRecommendations(riskLevel, entities)
      };
    } catch (error) {
      console.error('Vulnerability analysis failed:', error);
      return {
        riskLevel: 'UNKNOWN',
        sentiment: { label: 'NEUTRAL', score: 0.5 },
        summary: vulnerabilityText.substring(0, 100) + '...',
        entities: [],
        confidence: 0,
        recommendations: ['Review vulnerability manually'],
        error: error.message
      };
    }
  }

  /**
   * Generate security recommendations based on analysis
   */
  generateRecommendations(riskLevel, entities) {
    const recommendations = [];
    
    if (riskLevel === 'HIGH') {
      recommendations.push('🚨 Immediate action required - High risk vulnerability detected');
      recommendations.push('🔒 Implement additional security controls');
      recommendations.push('📋 Create incident response plan');
    } else if (riskLevel === 'MEDIUM') {
      recommendations.push('⚠️ Review and address within 48 hours');
      recommendations.push('🛡️ Consider additional monitoring');
    } else {
      recommendations.push('✅ Low priority - schedule for next maintenance window');
    }
    
    // Add entity-specific recommendations
    entities.forEach(entity => {
      if (entity.entity.includes('PER')) {
        recommendations.push('👤 Review user access controls');
      } else if (entity.entity.includes('ORG')) {
        recommendations.push('🏢 Check organization security policies');
      } else if (entity.entity.includes('LOC')) {
        recommendations.push('🌍 Verify geographic access restrictions');
      }
    });
    
    return recommendations;
  }

  /**
   * Batch analyze multiple vulnerabilities
   */
  async batchAnalyzeVulnerabilities(vulnerabilities) {
    const results = [];
    
    for (const vuln of vulnerabilities) {
      try {
        const analysis = await this.analyzeVulnerability(vuln.description || vuln.name);
        results.push({
          id: vuln.id,
          name: vuln.name,
          analysis
        });
      } catch (error) {
        results.push({
          id: vuln.id,
          name: vuln.name,
          analysis: {
            riskLevel: 'UNKNOWN',
            error: error.message
          }
        });
      }
    }
    
    return results;
  }

  /**
   * Generate AI-powered scan summary
   */
  async generateScanSummary(scanResults) {
    try {
      const vulnerabilities = scanResults.vulnerabilities || [];
      
      if (vulnerabilities.length === 0) {
        return {
          summary: 'No vulnerabilities found. The target appears to be secure.',
          riskLevel: 'LOW',
          confidence: 95
        };
      }
      
      // Analyze each vulnerability
      const analyses = await this.batchAnalyzeVulnerabilities(vulnerabilities);
      
      // Count risk levels
      const riskCounts = analyses.reduce((acc, item) => {
        const level = item.analysis.riskLevel;
        acc[level] = (acc[level] || 0) + 1;
        return acc;
      }, {});
      
      // Determine overall risk
      let overallRisk = 'LOW';
      if (riskCounts.HIGH > 0) {
        overallRisk = 'HIGH';
      } else if (riskCounts.MEDIUM > 0) {
        overallRisk = 'MEDIUM';
      }
      
      // Generate summary text
      const summaryText = `Security scan completed. Found ${vulnerabilities.length} vulnerabilities: ` +
        `${riskCounts.HIGH || 0} high risk, ${riskCounts.MEDIUM || 0} medium risk, ${riskCounts.LOW || 0} low risk. ` +
        `Overall security posture: ${overallRisk} risk.`;
      
      return {
        summary: summaryText,
        riskLevel: overallRisk,
        confidence: 85,
        vulnerabilityCounts: riskCounts,
        detailedAnalyses: analyses
      };
    } catch (error) {
      console.error('Scan summary generation failed:', error);
      return {
        summary: 'Unable to generate AI summary. Please review scan results manually.',
        riskLevel: 'UNKNOWN',
        confidence: 0,
        error: error.message
      };
    }
  }
}

// Create singleton instance
const huggingfaceNLP = new HuggingFaceNLPService();

export default huggingfaceNLP;
