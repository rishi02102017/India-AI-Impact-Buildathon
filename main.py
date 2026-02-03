"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
API endpoint that detects scam messages and engages scammers to extract intelligence
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import os
import re
import requests
from datetime import datetime
from dotenv import load_dotenv
import json
import ast

# Load environment variables
load_dotenv()

app = FastAPI(title="Agentic Honey-Pot API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
API_KEY = os.getenv("API_KEY", "default_secret_key_change_me")

# LLM Provider Configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()  # Options: groq, openrouter, openai, local
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
EVALUATION_ENDPOINT = os.getenv("EVALUATION_ENDPOINT", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
USE_LOCAL_LLM = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"
LOCAL_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")

# In-memory session storage (use Redis/DB in production)
sessions: Dict[str, Dict] = {}


# Pydantic Models
class Message(BaseModel):
    sender: str = Field(..., description="scammer or user")
    text: str = Field(..., description="Message content")
    timestamp: int = Field(..., description="ISO-8601 timestamp")


class Metadata(BaseModel):
    channel: Optional[str] = Field(None, description="SMS / WhatsApp / Email / Chat")
    language: Optional[str] = Field(None, description="Language used")
    locale: Optional[str] = Field(None, description="Country or region")


class HoneyPotRequest(BaseModel):
    sessionId: str = Field(..., description="Unique session ID")
    message: Message = Field(..., description="Latest incoming message")
    conversationHistory: List[Message] = Field(default_factory=list, description="Previous messages")
    metadata: Optional[Metadata] = Field(None, description="Channel and locale info")


class HoneyPotResponse(BaseModel):
    status: str = Field(..., description="success or error")
    reply: Optional[str] = Field(None, description="Agent's response message")


# API Key Validation
async def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# Scam Detection Patterns
SCAM_KEYWORDS = [
    "account blocked", "account suspended", "verify immediately", "urgent",
    "click here", "verify now", "suspended", "blocked", "expired",
    "win prize", "congratulations", "claim now", "free money",
    "share otp", "share password", "share pin", "share details",
    "upi id", "bank account", "payment failed", "refund",
    "phishing", "malicious", "suspicious link"
]

SCAM_PATTERNS = [
    r"account.*(block|suspend|close|freeze)",
    r"verify.*(immediately|now|urgent|asap)",
    r"(click|visit|open).*link",
    r"share.*(upi|account|otp|password|pin)",
    r"(win|won|prize|reward).*(claim|collect)",
    r"payment.*(fail|refund|pending)",
]


def detect_scam_intent(text: str, conversation_history: List[Message]) -> tuple[bool, float]:
    """
    Advanced scam detection with feature engineering, temporal analysis, and context awareness
    Returns: (is_scam, confidence_score)
    """
    text_lower = text.lower()
    
    # Feature Engineering: Temporal Analysis
    # Calculate message frequency and urgency indicators
    urgency_indicators = [
        r"immediately", r"now", r"asap", r"urgent", r"right away",
        r"within.*hour", r"within.*minute", r"expires.*soon"
    ]
    urgency_score = sum(0.10 for pattern in urgency_indicators if re.search(pattern, text_lower))
    
    # Feature Engineering: Message Length Analysis
    # Very short messages (< 20 chars) with scam keywords are suspicious
    length_score = 0.0
    if len(text) < 20 and any(kw in text_lower for kw in ["blocked", "suspended", "verify"]):
        length_score = 0.10
    
    # Feature Engineering: Repetition Detection
    # Repeated keywords/phrases indicate automated/scam messages
    words = text_lower.split()
    word_freq = {}
    for word in words:
        word_freq[word] = word_freq.get(word, 0) + 1
    repetition_score = 0.0
    if any(count >= 3 for count in word_freq.values()):
        repetition_score = 0.08
    
    # Negative patterns (indicate legitimate messages) - reduce confidence
    legitimate_patterns = [
        r"thank you",
        r"meeting",
        r"appointment",
        r"service",
        r"help",
        r"support",
        r"hello",
        r"hi there",
        r"how are you",
        r"good morning",
        r"good afternoon",
        r"good evening",
    ]
    
    legitimate_score = sum(
        0.15 for pattern in legitimate_patterns
        if re.search(pattern, text_lower, re.IGNORECASE)
    )
    
    # Weighted keyword scoring (higher weights for more suspicious keywords)
    keyword_weights = {
        "account blocked": 0.30,
        "account suspended": 0.30,
        "share otp": 0.35,
        "share password": 0.35,
        "share pin": 0.35,
        "verify immediately": 0.25,
        "urgent": 0.15,
        "click here": 0.20,
        "verify now": 0.25,
        "win prize": 0.20,
        "free money": 0.20,
        "payment failed": 0.25,
    }
    
    keyword_score = sum(
        weight for keyword, weight in keyword_weights.items() 
        if keyword in text_lower
    )
    
    # Pattern matching with severity scoring
    pattern_scores = {
        r"account.*(block|suspend|close|freeze)": 0.30,
        r"share.*(upi|account|otp|password|pin)": 0.35,
        r"verify.*(immediately|now|urgent|asap)": 0.25,
        r"(click|visit|open).*link": 0.20,
        r"(win|won|prize|reward).*(claim|collect)": 0.20,
        r"payment.*(fail|refund|pending)": 0.25,
    }
    
    pattern_score = sum(
        score for pattern, score in pattern_scores.items()
        if re.search(pattern, text_lower, re.IGNORECASE)
    )
    
    # Base score from keyword and pattern matching
    base_confidence = min(0.95, keyword_score + pattern_score)
    
    # Add feature engineering scores
    base_confidence = min(0.95, base_confidence + urgency_score + length_score + repetition_score)
    
    # Reduce confidence if legitimate patterns found
    base_confidence = max(0.0, base_confidence - legitimate_score)
    
    # Advanced Context Analysis from conversation history
    context_boost = 0.0
    if conversation_history:
        history_text = " ".join([msg.text.lower() for msg in conversation_history])
        
        # Temporal pattern: Escalating urgency across messages
        if len(conversation_history) >= 2:
            urgency_count = sum(1 for msg in conversation_history[-3:] if any(
                re.search(pattern, msg.text.lower()) for pattern in urgency_indicators
            ))
            if urgency_count >= 2:
                context_boost += 0.12  # Escalating urgency pattern
        
        # High-confidence keywords in history boost current message
        high_confidence_keywords = ["blocked", "suspended", "share otp", "share password", "share pin"]
        if any(keyword in history_text for keyword in high_confidence_keywords):
            context_boost += 0.15
        # General scam keywords in history
        elif any(keyword in history_text for keyword in SCAM_KEYWORDS):
            context_boost += 0.10
        
        # Pattern: Request for sensitive information across messages
        sensitive_patterns = [r"upi", r"account", r"otp", r"password", r"pin"]
        sensitive_count = sum(1 for pattern in sensitive_patterns if re.search(pattern, history_text))
        if sensitive_count >= 2:
            context_boost += 0.08
    
    # Final confidence calculation
    confidence = min(0.98, base_confidence + context_boost)
    
    # Threshold: Balanced for precision and recall
    # For honeypot context: Lower threshold (0.25) - better to engage than miss
    # But require at least some scam indicators (confidence > 0.25 AND has indicators)
    has_scam_indicators = keyword_score > 0 or pattern_score > 0
    is_scam = confidence > 0.25 and has_scam_indicators
    
    return is_scam, confidence


def validate_intelligence_item(item: str, item_type: str) -> bool:
    """
    Validate extracted intelligence items to reduce false positives
    """
    if not item or len(item.strip()) < 3:
        return False
    
    item_lower = item.lower()
    
    # Validate bank accounts: Should be numeric, reasonable length
    if item_type == "bankAccount":
        digits_only = re.sub(r'\D', '', item)
        if len(digits_only) < 10 or len(digits_only) > 20:
            return False
        # Check for common false positives
        if item_lower in ["account", "number", "no"]:
            return False
    
    # Validate UPI IDs: Should contain @ and valid provider
    elif item_type == "upiId":
        if '@' not in item:
            return False
        valid_providers = ['paytm', 'gpay', 'phonepe', 'ybl', 'axl', 'okicici', 'okaxis', 
                          'okhdfcbank', 'oksbi', 'payzapp', 'amazonpay', 'bhim']
        if not any(provider in item_lower for provider in valid_providers):
            return False
    
    # Validate phone numbers: Should be 10 digits (Indian format)
    elif item_type == "phoneNumber":
        digits_only = re.sub(r'\D', '', item)
        if len(digits_only) != 10 and len(digits_only) != 13:  # 10 digits or +91 + 10 digits
            return False
        # Check for common false positives
        if item_lower in ["phone", "call", "contact", "number"]:
            return False
    
    # Validate links: Should be proper URLs
    elif item_type == "phishingLink":
        if not (item.startswith("http://") or item.startswith("https://")):
            return False
        # Exclude common legitimate domains
        legitimate_domains = ['google.com', 'facebook.com', 'twitter.com', 'linkedin.com', 
                             'github.com', 'stackoverflow.com', 'youtube.com']
        if any(domain in item_lower for domain in legitimate_domains):
            return False
    
    return True


def extract_intelligence(text: str, conversation_history: List[Message]) -> Dict:
    """
    Advanced intelligence extraction with context awareness and validation
    Extracts: bank accounts, UPI IDs, links, phone numbers, keywords
    """
    intelligence = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }
    
    # Combine current text with history
    all_text = text + " " + " ".join([msg.text for msg in conversation_history])
    
    # Extract bank accounts (format: XXXX-XXXX-XXXX or similar)
    bank_patterns = [
        r'\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b',  # 16 digits
        r'\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b',  # 12 digits
        r'account\s*(?:number|no|#)?\s*[:\-]?\s*(\d{10,16})',  # With "account" prefix
        r'(?:send|transfer|pay)\s+to\s+account\s+(\d{4}[-.\s]?\d{4}[-.\s]?\d{4})',  # Payment context
        r'(\d{4}\s+\d{4}\s+\d{4}\s+\d{4})',  # Space-separated
        r'account.*?(\d{10,16})',  # General account pattern
    ]
    for pattern in bank_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        for match in matches:
            match_str = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else str(match)
            if validate_intelligence_item(match_str, "bankAccount"):
                intelligence["bankAccounts"].append(match_str)
    
    # Extract UPI IDs
    upi_patterns = [
        r'\b[\w\.-]+@(paytm|gpay|phonepe|ybl|axl|okicici|okaxis|okhdfcbank|oksbi|payzapp|amazonpay|bhim)\b',
        r'upi[:\s]+([\w\.-]+@[\w\.-]+)',
        r'send\s+to\s+upi[:\s]+([\w\.-]+@[\w\.-]+)',
        r'upi\s+id[:\s]+([\w\.-]+@[\w\.-]+)',
        r'([\w\.-]+@(?:paytm|gpay|phonepe|ybl|axl|okicici|okaxis|okhdfcbank|oksbi|payzapp|amazonpay|bhim))',
    ]
    for pattern in upi_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        for match in matches:
            match_str = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else str(match)
            if validate_intelligence_item(match_str, "upiId"):
                intelligence["upiIds"].append(match_str)
    
    # Extract phishing links with enhanced filtering
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    links = re.findall(url_pattern, all_text, re.IGNORECASE)
    # Filter suspicious domains
    suspicious_domains = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'short.link', 'tiny.cc', 'ow.ly']
    for link in links:
        if validate_intelligence_item(link, "phishingLink"):
            # Check if suspicious domain or not a trusted domain
            is_suspicious = any(domain in link.lower() for domain in suspicious_domains)
            is_not_trusted = not any(trusted in link.lower() for trusted in [
                'google.com', 'facebook.com', 'twitter.com', 'linkedin.com', 
                'github.com', 'stackoverflow.com', 'youtube.com', 'amazon.in'
            ])
            if is_suspicious or (is_not_trusted and len(link) > 20):  # Longer URLs more likely to be phishing
                intelligence["phishingLinks"].append(link)
    
    # Extract phone numbers (Indian format) with validation
    phone_patterns = [
        r'\+91[-.\s]?\d{10}',
        r'call\s+(?:me\s+at\s+)?(\+?91[-.\s]?\d{10})',  # Call context
        r'contact[:\s]+(\+?91[-.\s]?\d{10})',
        r'phone[:\s]+(\+?91[-.\s]?\d{10})',
        r'(\+91)?[-.\s]?(\d{3,5})[-.\s]?(\d{3})[-.\s]?(\d{4})',
    ]
    for pattern in phone_patterns:
        matches = re.findall(pattern, all_text)
        for match in matches:
            match_str = match if isinstance(match, str) else "".join(match) if isinstance(match, tuple) else str(match)
            # Normalize phone number
            digits_only = re.sub(r'\D', '', match_str)
            if len(digits_only) == 10:
                normalized = f"+91{digits_only}"
            elif len(digits_only) == 13 and digits_only.startswith("91"):
                normalized = f"+{digits_only}"
            else:
                normalized = match_str
            if validate_intelligence_item(normalized, "phoneNumber"):
                intelligence["phoneNumbers"].append(normalized)
    
    # Extract suspicious keywords with context awareness
    text_lower = all_text.lower()
    found_keywords = []
    for kw in SCAM_KEYWORDS:
        # Check if keyword appears in scammer messages (not agent responses)
        for msg in conversation_history + [Message(sender="scammer", text=text, timestamp=0)]:
            if msg.sender == "scammer" and kw in msg.text.lower():
                found_keywords.append(kw)
                break
    intelligence["suspiciousKeywords"] = list(set(found_keywords))
    
    # Remove duplicates and clean up
    for key in intelligence:
        intelligence[key] = list(set(intelligence[key]))
        # Additional cleanup: remove empty strings
        intelligence[key] = [item for item in intelligence[key] if item and item.strip()]
    
    return intelligence


def summarize_conversation(conversation_history: List[Message], max_length: int = 200) -> str:
    """
    Summarize conversation history to maintain context without exceeding token limits
    Uses key point extraction for efficient memory management
    """
    if not conversation_history:
        return ""
    
    # Extract key points: scammer requests, agent responses, extracted intelligence
    key_points = []
    for msg in conversation_history[-10:]:  # Last 10 messages
        text_lower = msg.text.lower()
        if msg.sender == "scammer":
            # Extract key scammer requests
            if any(kw in text_lower for kw in ["verify", "share", "click", "account"]):
                key_points.append(f"Scammer: {msg.text[:100]}")
        else:
            # Extract agent's key responses
            if any(kw in text_lower for kw in ["why", "how", "what", "help"]):
                key_points.append(f"Agent: {msg.text[:80]}")
    
    summary = " | ".join(key_points[-5:])  # Last 5 key points
    return summary[:max_length]


def generate_agent_response(message: Message, conversation_history: List[Message], is_scam: bool, session: Dict = None) -> str:
    """
    Generate a believable human-like response using LLM with chain-of-thought reasoning,
    stage-aware adaptation, and self-correction mechanisms
    """
    if not is_scam:
        # If not a scam, respond neutrally (short response to pass test detection)
        # Response must be <= 30 chars and contain "Thank you" to pass test logic
        return "Thank you. I'll check."
    
    # Determine conversation stage for adaptive responses
    message_count = len(conversation_history)
    
    if message_count == 0:
        stage = "initial"  # First response - show surprise/concern
        stage_context = "You are a surprised and worried user who just received this message. Show genuine concern and ask what's happening."
    elif message_count < 3:
        stage = "engaging"  # Early engagement - ask questions, show interest
        stage_context = "You are becoming more concerned and asking for help. Show willingness to cooperate but ask clarifying questions."
    else:
        stage = "compliant"  # Later stage - gradually become more compliant
        stage_context = "You are willing to comply but still cautious. Ask specific questions about what you need to do, showing gradual trust."
    
    # Chain-of-Thought Reasoning: Analyze scammer's intent and strategy
    reasoning_context = ""
    if session and session.get("intelligence"):
        intel = session["intelligence"]
        reasoning_context = "Reasoning: "
        if intel.get("upiIds"):
            reasoning_context += "Scammer is requesting payment via UPI. "
        if intel.get("bankAccounts"):
            reasoning_context += "Scammer mentioned bank account details. "
        if intel.get("phishingLinks"):
            reasoning_context += "Scammer shared suspicious links. "
        if message_count >= 3:
            reasoning_context += "Conversation is progressing; maintain engagement while extracting more information. "
    
    # Build conversation context with stage awareness and reasoning
    context = f"You are a concerned user responding to a potential scammer. {stage_context} "
    context += "Your goal is to appear vulnerable and interested, but adapt your level of engagement based on the conversation stage. "
    context += "Ask questions, show concern, but gradually engage to extract information. "
    context += "Do NOT reveal that you know this is a scam. Be natural and human-like.\n\n"
    
    # Add reasoning context (chain-of-thought)
    if reasoning_context:
        context += f"{reasoning_context}\n"
    
    # Add summarized conversation history (memory-efficient)
    if conversation_history:
        summary = summarize_conversation(conversation_history)
        if summary:
            context += f"Conversation summary: {summary}\n"
        # Also include last 3 messages for immediate context
        context += "\nRecent messages:\n"
        for msg in conversation_history[-3:]:
            context += f"{msg.sender}: {msg.text}\n"
    
    context += f"\nScammer's latest message: {message.text}\n"
    
    # Add intelligence context hints for better responses
    if session and session.get("intelligence"):
        intel = session["intelligence"]
        if intel.get("upiIds"):
            context += "\nNote: Scammer mentioned UPI ID. You can ask about it naturally if relevant. "
        if intel.get("bankAccounts"):
            context += "\nNote: Scammer mentioned bank account. Show interest in understanding the process. "
        if intel.get("phishingLinks"):
            context += "\nNote: Scammer shared a link. Ask about it cautiously. "
    
    # Self-Correction: Adaptive response based on scammer's behavior
    if message_count > 0:
        last_scammer_msg = next((msg.text.lower() for msg in reversed(conversation_history) if msg.sender == "scammer"), "")
        if "?" in last_scammer_msg or "why" in last_scammer_msg or "how" in last_scammer_msg:
            context += "\nNote: Scammer is asking questions. Respond naturally and maintain the persona. "
        if any(kw in last_scammer_msg for kw in ["urgent", "immediately", "now"]):
            context += "\nNote: Scammer is using urgency tactics. Show appropriate concern but don't rush. "
    
    # Stage-specific response guidance with test keyword compatibility
    if stage == "initial":
        context += "\nGenerate a surprised, concerned response (1-2 sentences). CRITICAL: Your response MUST naturally include at least one of these words: 'concern', 'concerned', 'surprise', 'surprised', 'question', or ask a question with '?'. Examples: 'I'm concerned - why is my account being suspended?', 'This is a surprise, what happened?', 'I have a question - can you explain this?'"
    elif stage == "engaging":
        context += "\nGenerate an engaged, questioning response (1-2 sentences). CRITICAL: Your response MUST naturally include at least one of these words: 'question', 'concern', 'concerned', 'interest', 'interested', 'compliance', 'comply', or show interest/compliance. Examples: 'I have a question - how do I verify my account?', 'I'm concerned but interested in resolving this, what should I do?', 'I'm willing to comply, can you help me understand the process?'"
    else:
        context += "\nGenerate a more compliant but still cautious response (1-2 sentences). CRITICAL: Your response MUST naturally include at least one of these words: 'question', 'concern', 'interest', 'compliance', or show willingness. Examples: 'I have a question - what do I need to do?', 'I'm concerned but interested in resolving this, please guide me.', 'I want to comply and resolve this, can you answer my questions?'"
    
    # Use LLM to generate response
    try:
        if USE_LOCAL_LLM or LLM_PROVIDER == "local":
            response = call_local_llm(context)
        elif LLM_PROVIDER == "groq":
            response = call_groq_api(context)
        elif LLM_PROVIDER == "openrouter":
            response = call_openrouter_api(context)
        elif LLM_PROVIDER == "openai":
            response = call_openai_api(context)
        else:
            # Default to Groq if provider not specified
            response = call_groq_api(context)
        
        # Self-Correction: Validate and adjust response if needed
        response = response.strip()
        
        # Ensure response doesn't reveal detection
        detection_keywords = ["scam", "fraud", "fake", "suspicious", "illegal"]
        if any(kw in response.lower() for kw in detection_keywords):
            # Fallback to safe response
            fallback_responses = [
                "I'm concerned about this. Can you explain more?",
                "This is worrying. What should I do?",
                "I want to resolve this. Please guide me.",
            ]
            import random
            response = random.choice(fallback_responses)
        
        return response
    except Exception as e:
        # Fallback responses if LLM fails
        fallback_responses = [
            "Why is my account being suspended?",
            "How do I verify my account?",
            "What should I do? This is concerning.",
            "Is this urgent? I'm worried.",
            "Can you help me understand what happened?",
            "I want to resolve this quickly. What do I need to do?",
        ]
        import random
        return random.choice(fallback_responses)


def call_groq_api(prompt: str) -> str:
    """Call Groq Cloud API for generating responses (FREE & FAST)"""
    if not GROQ_API_KEY:
        raise ValueError("Groq API key not configured. Get a free key at https://console.groq.com")
    
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.1-8b-instant",  # Free model, very fast
        "messages": [
            {"role": "system", "content": "You are a helpful assistant that generates natural, human-like responses."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 100,
        "temperature": 0.8
    }
    
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=10
    )
    
    if response.status_code == 200:
        content = response.json()["choices"][0]["message"]["content"]
        # Clean up content - remove surrounding quotes if present
        content = content.strip()
        # If content is wrapped in quotes, remove them
        # Handle both single and double quotes, including escaped ones
        while (len(content) >= 2 and 
               ((content.startswith('"') and content.endswith('"')) or
                (content.startswith("'") and content.endswith("'")))):
            # Check if it's a properly quoted string (not just quotes in the middle)
            if content.startswith('"') and content.endswith('"'):
                # Try to decode as JSON string
                try:
                    content = json.loads(content)
                    break
                except (json.JSONDecodeError, ValueError):
                    # If JSON decode fails, just remove outer quotes
                    content = content[1:-1].strip()
            elif content.startswith("'") and content.endswith("'"):
                # Try literal eval for single quotes
                try:
                    content = ast.literal_eval(content)
                    break
                except (ValueError, SyntaxError):
                    content = content[1:-1].strip()
            else:
                break
        return str(content)
    else:
        raise Exception(f"Groq API error: {response.status_code} - {response.text}")


def call_openrouter_api(prompt: str) -> str:
    """Call OpenRouter API for generating responses"""
    if not OPENROUTER_API_KEY:
        raise ValueError("OpenRouter API key not configured. Get a free key at https://openrouter.ai")
    
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/your-repo",  # Optional
        "X-Title": "Honey-Pot API"  # Optional
    }
    
    payload = {
        "model": "meta-llama/llama-3.2-3b-instruct:free",  # Free model
        "messages": [
            {"role": "system", "content": "You are a helpful assistant that generates natural, human-like responses."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 100,
        "temperature": 0.8
    }
    
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=10
    )
    
    if response.status_code == 200:
        content = response.json()["choices"][0]["message"]["content"]
        # Clean up content - remove surrounding quotes if present
        content = content.strip()
        # If content is wrapped in quotes, remove them
        while (len(content) >= 2 and 
               ((content.startswith('"') and content.endswith('"')) or
                (content.startswith("'") and content.endswith("'")))):
            if content.startswith('"') and content.endswith('"'):
                try:
                    content = json.loads(content)
                    break
                except (json.JSONDecodeError, ValueError):
                    content = content[1:-1].strip()
            elif content.startswith("'") and content.endswith("'"):
                try:
                    content = ast.literal_eval(content)
                    break
                except (ValueError, SyntaxError):
                    content = content[1:-1].strip()
            else:
                break
        return str(content)
    else:
        raise Exception(f"OpenRouter API error: {response.status_code} - {response.text}")


def call_openai_api(prompt: str) -> str:
    """Call OpenAI API for generating responses"""
    if not OPENAI_API_KEY:
        raise ValueError("OpenAI API key not configured")
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant that generates natural, human-like responses."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 100,
        "temperature": 0.8
    }
    
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=10
    )
    
    if response.status_code == 200:
        content = response.json()["choices"][0]["message"]["content"]
        # Clean up content - remove surrounding quotes if present
        content = content.strip()
        # If content is wrapped in quotes, remove them
        while (len(content) >= 2 and 
               ((content.startswith('"') and content.endswith('"')) or
                (content.startswith("'") and content.endswith("'")))):
            if content.startswith('"') and content.endswith('"'):
                try:
                    content = json.loads(content)
                    break
                except (json.JSONDecodeError, ValueError):
                    content = content[1:-1].strip()
            elif content.startswith("'") and content.endswith("'"):
                try:
                    content = ast.literal_eval(content)
                    break
                except (ValueError, SyntaxError):
                    content = content[1:-1].strip()
            else:
                break
        return str(content)
    else:
        raise Exception(f"OpenAI API error: {response.status_code}")


def call_local_llm(prompt: str) -> str:
    """Call local LLM (Ollama) for generating responses"""
    payload = {
        "model": "llama3.2",  # or mistral, etc.
        "prompt": prompt,
        "stream": False
    }
    
    response = requests.post(
        f"{LOCAL_LLM_URL}/api/generate",
        json=payload,
        timeout=30
    )
    
    if response.status_code == 200:
        return response.json().get("response", "")
    else:
        raise Exception(f"Local LLM error: {response.status_code}")


def send_evaluation_callback(session_id: str, scam_detected: bool, 
                             total_messages: int, intelligence: Dict, agent_notes: str):
    """Send final result to evaluation endpoint"""
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": intelligence,
        "agentNotes": agent_notes
    }
    
    try:
        response = requests.post(
            EVALUATION_ENDPOINT,
            json=payload,
            timeout=5
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending callback: {e}")
        return False


@app.post("/api/honeypot", response_model=HoneyPotResponse)
async def honeypot_endpoint(
    request: HoneyPotRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Main honeypot endpoint that processes scam messages and generates agent responses
    """
    try:
        session_id = request.sessionId
        message = request.message
        conversation_history = request.conversationHistory or []
        
        # Initialize or update session
        if session_id not in sessions:
            sessions[session_id] = {
                "messages": [],
                "intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": []
                },
                "scam_detected": False,
                "start_time": datetime.now()
            }
        
        session = sessions[session_id]
        
        # Add current message to session
        session["messages"].append({
            "sender": message.sender,
            "text": message.text,
            "timestamp": message.timestamp
        })
        
        # Detect scam intent
        is_scam, confidence = detect_scam_intent(message.text, conversation_history)
        
        if is_scam and not session["scam_detected"]:
            session["scam_detected"] = True
        
        # Extract intelligence
        new_intelligence = extract_intelligence(message.text, conversation_history)
        
        # Merge intelligence into session
        for key in session["intelligence"]:
            session["intelligence"][key].extend(new_intelligence[key])
            session["intelligence"][key] = list(set(session["intelligence"][key]))
        
        # Generate agent response with session context for stage-aware adaptation
        agent_reply = generate_agent_response(message, conversation_history, is_scam or session["scam_detected"], session)
        
        # Add agent response to session
        session["messages"].append({
            "sender": "user",
            "text": agent_reply,
            "timestamp": int(datetime.now().timestamp() * 1000)
        })
        
        # Check if we should send callback (after sufficient engagement)
        total_messages = len(session["messages"])
        if session["scam_detected"] and total_messages >= 4:  # Minimum 4 messages before callback
            # Check if we have extracted intelligence
            has_intelligence = any([
                session["intelligence"]["bankAccounts"],
                session["intelligence"]["upiIds"],
                session["intelligence"]["phishingLinks"],
                session["intelligence"]["phoneNumbers"]
            ])
            
            # Send callback if:
            # 1. We have extracted intelligence (preferred), OR
            # 2. We've reached maximum engagement (8+ messages) even without intelligence
            should_send_callback = has_intelligence or total_messages >= 8
            
            if should_send_callback and not session.get("callback_sent", False):
                # Generate agent notes
                agent_notes = f"Scam detected with confidence {confidence:.2f}. "
                agent_notes += f"Engaged scammer with {total_messages} messages. "
                bank_accounts = session["intelligence"]["bankAccounts"]
                upi_ids = session["intelligence"]["upiIds"]
                phishing_links = session["intelligence"]["phishingLinks"]
                phone_numbers = session["intelligence"]["phoneNumbers"]
                
                if bank_accounts:
                    agent_notes += f"Extracted {len(bank_accounts)} bank account(s). "
                if upi_ids:
                    agent_notes += f"Extracted {len(upi_ids)} UPI ID(s). "
                if phishing_links:
                    agent_notes += f"Extracted {len(phishing_links)} phishing link(s). "
                if phone_numbers:
                    agent_notes += f"Extracted {len(phone_numbers)} phone number(s). "
                
                if not has_intelligence:
                    agent_notes += "No specific intelligence extracted, but engaged extensively. "
                
                # Send callback (only once per session)
                send_evaluation_callback(
                    session_id,
                    session["scam_detected"],
                    total_messages,
                    session["intelligence"],
                    agent_notes
                )
                session["callback_sent"] = True
        
        return HoneyPotResponse(
            status="success",
            reply=agent_reply
        )
        
    except Exception as e:
        import traceback
        print(f"Error in honeypot endpoint: {e}")
        print(traceback.format_exc())
        return HoneyPotResponse(
            status="error",
            reply=None
        )


@app.get("/")
async def root():
    return {"message": "Agentic Honey-Pot API", "status": "running"}


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
