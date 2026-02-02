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
    Detect if a message contains scam intent
    Returns: (is_scam, confidence_score)
    """
    text_lower = text.lower()
    
    # Pattern matching
    keyword_matches = sum(1 for keyword in SCAM_KEYWORDS if keyword in text_lower)
    pattern_matches = sum(1 for pattern in SCAM_PATTERNS if re.search(pattern, text_lower, re.IGNORECASE))
    
    # Calculate confidence
    confidence = min(0.95, 0.3 + (keyword_matches * 0.15) + (pattern_matches * 0.2))
    
    # Check conversation history for scam patterns
    if conversation_history:
        history_text = " ".join([msg.text.lower() for msg in conversation_history])
        if any(keyword in history_text for keyword in SCAM_KEYWORDS):
            confidence = min(0.98, confidence + 0.1)
    
    is_scam = confidence > 0.4
    
    return is_scam, confidence


def extract_intelligence(text: str, conversation_history: List[Message]) -> Dict:
    """
    Extract intelligence from messages: bank accounts, UPI IDs, links, phone numbers, keywords
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
        r'account.*?(\d{10,16})',
    ]
    for pattern in bank_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        intelligence["bankAccounts"].extend(matches)
    
    # Extract UPI IDs
    upi_patterns = [
        r'\b[\w\.-]+@(paytm|gpay|phonepe|ybl|axl|okicici|okaxis|okhdfcbank|oksbi|payzapp|amazonpay)\b',
        r'upi[:\s]+([\w\.-]+@[\w\.-]+)',
        r'([\w\.-]+@[\w\.-]+)',
    ]
    for pattern in upi_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        intelligence["upiIds"].extend([m if isinstance(m, str) else m[0] for m in matches])
    
    # Extract phishing links
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    links = re.findall(url_pattern, all_text, re.IGNORECASE)
    # Filter suspicious domains
    suspicious_domains = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'short.link']
    intelligence["phishingLinks"] = [
        link for link in links 
        if any(domain in link.lower() for domain in suspicious_domains) or 
        not any(trusted in link.lower() for trusted in ['google.com', 'facebook.com', 'twitter.com', 'linkedin.com'])
    ]
    
    # Extract phone numbers (Indian format)
    phone_patterns = [
        r'\+91[-.\s]?\d{10}',
        r'\b\d{10}\b',
        r'(\+91)?[-.\s]?(\d{3,5})[-.\s]?(\d{3})[-.\s]?(\d{4})',
    ]
    for pattern in phone_patterns:
        matches = re.findall(pattern, all_text)
        intelligence["phoneNumbers"].extend([m if isinstance(m, str) else "".join(m) for m in matches])
    
    # Extract suspicious keywords
    text_lower = all_text.lower()
    found_keywords = [kw for kw in SCAM_KEYWORDS if kw in text_lower]
    intelligence["suspiciousKeywords"] = list(set(found_keywords))
    
    # Remove duplicates
    for key in intelligence:
        intelligence[key] = list(set(intelligence[key]))
    
    return intelligence


def generate_agent_response(message: Message, conversation_history: List[Message], is_scam: bool) -> str:
    """
    Generate a believable human-like response using LLM
    """
    if not is_scam:
        # If not a scam, respond neutrally
        return "Thank you for your message. I'll look into this."
    
    # Build conversation context
    context = "You are a concerned user responding to a potential scammer. "
    context += "Your goal is to appear vulnerable and interested, but not too eager. "
    context += "Ask questions, show concern, but gradually engage to extract information. "
    context += "Do NOT reveal that you know this is a scam. Be natural and human-like.\n\n"
    
    # Add conversation history
    if conversation_history:
        context += "Previous conversation:\n"
        for msg in conversation_history[-5:]:  # Last 5 messages for context
            context += f"{msg.sender}: {msg.text}\n"
    
    context += f"\nScammer's latest message: {message.text}\n"
    context += "\nGenerate a natural, concerned human response (1-2 sentences max). "
    context += "Examples: 'Why is my account being suspended?', 'How do I verify?', 'What should I do?', 'Is this urgent?'"
    
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
        return response.strip()
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
        
        # Generate agent response
        agent_reply = generate_agent_response(message, conversation_history, is_scam or session["scam_detected"])
        
        # Add agent response to session
        session["messages"].append({
            "sender": "user",
            "text": agent_reply,
            "timestamp": int(datetime.now().timestamp() * 1000)
        })
        
        # Check if we should send callback (after sufficient engagement)
        total_messages = len(session["messages"])
        if session["scam_detected"] and total_messages >= 4:  # Minimum 4 messages before callback
            # Generate agent notes
            agent_notes = f"Scam detected with confidence {confidence:.2f}. "
            agent_notes += f"Engaged scammer with {total_messages} messages. "
            bank_accounts = session["intelligence"]["bankAccounts"]
            upi_ids = session["intelligence"]["upiIds"]
            phishing_links = session["intelligence"]["phishingLinks"]
            if bank_accounts:
                agent_notes += f"Extracted {len(bank_accounts)} bank account(s). "
            if upi_ids:
                agent_notes += f"Extracted {len(upi_ids)} UPI ID(s). "
            if phishing_links:
                agent_notes += f"Extracted {len(phishing_links)} phishing link(s). "
            
            # Send callback (only once per session)
            if not session.get("callback_sent", False):
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


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
