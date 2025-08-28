// server.js - Secure server that reads .env file
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = global.fetch;

require('dotenv').config();

const app = express();

// 🔑 API configuration from .env
const API_CONFIG = {
    OPENROUTER_KEY: process.env.OPENROUTER_API_KEY,
    OPENAI_KEY: process.env.OPENAI_API_KEY,
    PORT: process.env.PORT || 3001,
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS
        ? process.env.ALLOWED_ORIGINS.split(',')
        : ['http://localhost:3000', 'chrome-extension://<your-extension-id>']
};

// 🛡️ Middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// 🔐 CORS
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || API_CONFIG.ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

// 📊 Rate limiting
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100
});
app.use('/api/', limiter);

// 🤖 AI phishing analysis endpoint
app.post('/api/analyze-phishing', async (req, res) => {
    try {
        const { url, content } = req.body;
        console.log(`🔍 Analyzing: ${url}`);

        const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${API_CONFIG.OPENROUTER_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'openai/gpt-3.5-turbo',
                messages: [
                    {
                        role: 'system',
                        content: 'You are a cybersecurity expert. Analyze for phishing threats.'
                    },
                    {
                        role: 'user',
                        content: `Analyze this URL for phishing: ${url}\nContent: ${(content || '').substring(0, 500)}\n\nRespond with JSON: {"risk_level": "safe|suspicious|malicious", "confidence": 0-100, "threats": [], "reasoning": ""}`
                    }
                ],
                max_tokens: 1000,
                temperature: 0.3
            })
        });

        if (!response.ok) throw new Error(`AI API error: ${response.status}`);

        const data = await response.json();

        let analysis;
        try {
            analysis = JSON.parse(data.choices[0].message.content);
        } catch {
            analysis = {
                risk_level: "suspicious",
                confidence: 50,
                threats: [],
                reasoning: "AI did not return valid JSON"
            };
        }

        res.json({
            success: true,
            analysis,
            aiUsed: true,
            model: 'openai/gpt-3.5-turbo'
        });

    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ❤️ Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'Secure AI Proxy',
        version: '1.0.0',
        apiKeysLoaded: {
            openrouter: !!API_CONFIG.OPENROUTER_KEY,
            openai: !!API_CONFIG.OPENAI_KEY,
        }
    });
});

// 🚀 Start server
app.listen(API_CONFIG.PORT, () => {
    console.log(`🚀 Server running on port ${API_CONFIG.PORT}`);
    console.log(`🔑 OpenRouter API: ${API_CONFIG.OPENROUTER_KEY ? 'Loaded ✅' : 'Missing ❌'}`);
    console.log(`🔑 OpenAI API: ${API_CONFIG.OPENAI_KEY ? 'Loaded ✅' : 'Missing ❌'}`);
    console.log(`🛡️ CORS Origins: ${API_CONFIG.ALLOWED_ORIGINS.join(', ')}`);
});
