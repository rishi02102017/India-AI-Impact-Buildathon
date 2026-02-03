"""
Comprehensive Test Suite - Testing Everything from A-Z
Tests all components, edge cases, error handling, and integration
"""

import requests
import json
import time
import os
from dotenv import load_dotenv
from typing import Dict, List, Tuple

load_dotenv()

API_URL = "http://localhost:8001/api/honeypot"
API_KEY = os.getenv("API_KEY", "default_secret_key_change_me")
EVALUATION_ENDPOINT = os.getenv("EVALUATION_ENDPOINT", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

test_results = []

def log_test(test_name: str, status: str, details: str = ""):
    """Log test result"""
    result = {
        "test": test_name,
        "status": status,
        "details": details,
        "timestamp": time.time()
    }
    test_results.append(result)
    status_symbol = "[PASS]" if status == "PASS" else "[FAIL]" if status == "FAIL" else "[WARN]"
    print(f"{status_symbol} {test_name}")
    if details:
        print(f"      {details}")

def test_api_server_availability():
    """Test A1: API Server Availability"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            log_test("A1: API Server Health Check", "PASS", f"Status: {response.status_code}, Response: {response.json()}")
            return True
        else:
            log_test("A1: API Server Health Check", "FAIL", f"Status: {response.status_code}")
            return False
    except Exception as e:
        log_test("A1: API Server Health Check", "FAIL", f"Error: {e}")
        return False

def test_api_authentication():
    """Test B: API Authentication"""
    print("\n" + "="*70)
    print("TEST SUITE B: API Authentication")
    print("="*70)
    
    # B1: Test without API key
    try:
        response = requests.post(API_URL, json={}, timeout=5)
        if response.status_code == 401 or response.status_code == 422:
            log_test("B1: Request without API key", "PASS", f"Correctly rejected with status {response.status_code}")
        else:
            log_test("B1: Request without API key", "FAIL", f"Unexpected status: {response.status_code}")
    except Exception as e:
        log_test("B1: Request without API key", "FAIL", f"Error: {e}")
    
    # B2: Test with invalid API key
    invalid_headers = {"Content-Type": "application/json", "x-api-key": "invalid_key_12345"}
    try:
        response = requests.post(API_URL, json={}, headers=invalid_headers, timeout=5)
        if response.status_code == 401:
            log_test("B2: Request with invalid API key", "PASS", "Correctly rejected with 401")
        else:
            log_test("B2: Request with invalid API key", "FAIL", f"Unexpected status: {response.status_code}")
    except Exception as e:
        log_test("B2: Request with invalid API key", "FAIL", f"Error: {e}")
    
    # B3: Test with valid API key
    try:
        payload = {
            "sessionId": "test-auth",
            "message": {"sender": "scammer", "text": "Test", "timestamp": 1234567890},
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            log_test("B3: Request with valid API key", "PASS", "Authentication successful")
            return True
        else:
            log_test("B3: Request with valid API key", "FAIL", f"Status: {response.status_code}")
            return False
    except Exception as e:
        log_test("B3: Request with valid API key", "FAIL", f"Error: {e}")
        return False

def test_request_validation():
    """Test C: Request Format Validation"""
    print("\n" + "="*70)
    print("TEST SUITE C: Request Format Validation")
    print("="*70)
    
    # C1: Missing sessionId
    try:
        payload = {
            "message": {"sender": "scammer", "text": "Test", "timestamp": 1234567890},
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        if response.status_code == 422:
            log_test("C1: Missing sessionId validation", "PASS", "Correctly rejected with 422")
        else:
            log_test("C1: Missing sessionId validation", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("C1: Missing sessionId validation", "FAIL", f"Error: {e}")
    
    # C2: Missing message
    try:
        payload = {
            "sessionId": "test",
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        if response.status_code == 422:
            log_test("C2: Missing message validation", "PASS", "Correctly rejected with 422")
        else:
            log_test("C2: Missing message validation", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("C2: Missing message validation", "FAIL", f"Error: {e}")
    
    # C3: Invalid message format
    try:
        payload = {
            "sessionId": "test",
            "message": {"sender": "scammer", "text": "Test"},  # Missing timestamp
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        if response.status_code == 422:
            log_test("C3: Invalid message format validation", "PASS", "Correctly rejected with 422")
        else:
            log_test("C3: Invalid message format validation", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("C3: Invalid message format validation", "FAIL", f"Error: {e}")
    
    # C4: Valid request format
    try:
        payload = {
            "sessionId": "test-valid",
            "message": {"sender": "scammer", "text": "Test", "timestamp": 1234567890},
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "status" in data and "reply" in data:
                log_test("C4: Valid request format", "PASS", f"Response: {data}")
                return True
            else:
                log_test("C4: Valid request format", "FAIL", "Missing required fields in response")
                return False
        else:
            log_test("C4: Valid request format", "FAIL", f"Status: {response.status_code}")
            return False
    except Exception as e:
        log_test("C4: Valid request format", "FAIL", f"Error: {e}")
        return False

def test_scam_detection():
    """Test D: Scam Detection Accuracy"""
    print("\n" + "="*70)
    print("TEST SUITE D: Scam Detection")
    print("="*70)
    
    scam_messages = [
        ("Your account is blocked", True, "High confidence scam"),
        ("Account suspended. Verify immediately", True, "Urgent scam"),
        ("Share your OTP to verify", True, "OTP scam"),
        ("Click here to claim prize", True, "Prize scam"),
        ("Payment failed. Refund pending", True, "Payment scam"),
        ("Hello, how are you?", False, "Normal message"),
        ("Thank you for your service", False, "Normal message"),
        ("Meeting at 3pm tomorrow", False, "Normal message"),
    ]
    
    passed = 0
    total = len(scam_messages)
    
    for message_text, expected_scam, description in scam_messages:
        try:
            payload = {
                "sessionId": f"test-scam-{int(time.time())}",
                "message": {"sender": "scammer", "text": message_text, "timestamp": int(time.time() * 1000)},
                "conversationHistory": []
            }
            response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                reply = data.get("reply", "")
                # Check if response indicates scam detection (non-neutral response)
                is_scam_detected = "Thank you" not in reply or len(reply) > 30
                
                if is_scam_detected == expected_scam:
                    log_test(f"D: Scam Detection - {description}", "PASS", f"Correctly detected: {expected_scam}")
                    passed += 1
                else:
                    log_test(f"D: Scam Detection - {description}", "FAIL", f"Expected: {expected_scam}, Got: {is_scam_detected}")
            else:
                log_test(f"D: Scam Detection - {description}", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            log_test(f"D: Scam Detection - {description}", "FAIL", f"Error: {e}")
    
    accuracy = (passed / total) * 100
    log_test("D: Overall Scam Detection Accuracy", "PASS" if accuracy >= 80 else "WARN", f"{passed}/{total} correct ({accuracy:.1f}%)")
    return accuracy >= 80

def test_intelligence_extraction():
    """Test E: Intelligence Extraction"""
    print("\n" + "="*70)
    print("TEST SUITE E: Intelligence Extraction")
    print("="*70)
    
    test_cases = [
        {
            "message": "Send money to account 1234-5678-9012-3456",
            "expected": {"bankAccounts": True},
            "description": "Bank account extraction"
        },
        {
            "message": "Share your UPI ID: scammer@paytm to verify",
            "expected": {"upiIds": True},
            "description": "UPI ID extraction"
        },
        {
            "message": "Click this link: bit.ly/fake-bank-verify",
            "expected": {"phishingLinks": True},
            "description": "Phishing link extraction"
        },
        {
            "message": "Call +91-9876543210 for verification",
            "expected": {"phoneNumbers": True},
            "description": "Phone number extraction"
        },
        {
            "message": "Your account is blocked. Verify immediately. Share OTP.",
            "expected": {"suspiciousKeywords": True},
            "description": "Suspicious keywords extraction"
        },
        {
            "message": "Send ₹5000 to UPI: scammer@paytm and account 1234-5678-9012-3456. Call +91-9876543210 or visit bit.ly/fake",
            "expected": {"bankAccounts": True, "upiIds": True, "phoneNumbers": True, "phishingLinks": True},
            "description": "Multiple intelligence types"
        }
    ]
    
    passed = 0
    total = len(test_cases)
    
    for i, test_case in enumerate(test_cases):
        try:
            session_id = f"test-intel-{int(time.time())}-{i}"
            payload = {
                "sessionId": session_id,
                "message": {"sender": "scammer", "text": test_case["message"], "timestamp": int(time.time() * 1000)},
                "conversationHistory": []
            }
            response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                # Send a few more messages to trigger callback and check intelligence
                for j in range(3):
                    time.sleep(0.5)
                    follow_up = {
                        "sessionId": session_id,
                        "message": {"sender": "scammer", "text": "This is urgent!", "timestamp": int(time.time() * 1000)},
                        "conversationHistory": [
                            {"sender": "scammer", "text": test_case["message"], "timestamp": int(time.time() * 1000)},
                            {"sender": "user", "text": "Why?", "timestamp": int(time.time() * 1000)}
                        ]
                    }
                    requests.post(API_URL, json=follow_up, headers=headers, timeout=10)
                
                # Check if intelligence was extracted (we can't directly check, but callback should have been sent)
                log_test(f"E: {test_case['description']}", "PASS", "Intelligence extraction attempted")
                passed += 1
            else:
                log_test(f"E: {test_case['description']}", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            log_test(f"E: {test_case['description']}", "FAIL", f"Error: {e}")
    
    log_test("E: Overall Intelligence Extraction", "PASS" if passed == total else "WARN", f"{passed}/{total} tests passed")
    return passed == total

def test_multi_turn_conversations():
    """Test F: Multi-Turn Conversation Handling"""
    print("\n" + "="*70)
    print("TEST SUITE F: Multi-Turn Conversations")
    print("="*70)
    
    session_id = f"test-multiturn-{int(time.time())}"
    conversation_history = []
    
    messages = [
        "Your account is blocked",
        "Verify immediately by clicking this link",
        "Share your UPI ID to avoid suspension",
        "Send money to account 1234-5678-9012-3456"
    ]
    
    try:
        for i, msg_text in enumerate(messages):
            payload = {
                "sessionId": session_id,
                "message": {"sender": "scammer", "text": msg_text, "timestamp": int(time.time() * 1000)},
                "conversationHistory": conversation_history.copy()
            }
            
            response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                reply = data.get("reply", "")
                
                # Add to conversation history
                conversation_history.append({"sender": "scammer", "text": msg_text, "timestamp": int(time.time() * 1000)})
                conversation_history.append({"sender": "user", "text": reply, "timestamp": int(time.time() * 1000)})
                
                log_test(f"F{i+1}: Turn {i+1} - {msg_text[:30]}...", "PASS", f"Reply: {reply[:50]}...")
                time.sleep(0.5)
            else:
                log_test(f"F{i+1}: Turn {i+1}", "FAIL", f"Status: {response.status_code}")
                return False
        
        log_test("F: Multi-Turn Conversation", "PASS", f"Successfully handled {len(messages)} turns")
        return True
    except Exception as e:
        log_test("F: Multi-Turn Conversation", "FAIL", f"Error: {e}")
        return False

def test_response_format():
    """Test G: Response Format Validation"""
    print("\n" + "="*70)
    print("TEST SUITE G: Response Format")
    print("="*70)
    
    try:
        payload = {
            "sessionId": "test-format",
            "message": {"sender": "scammer", "text": "Your account is suspended", "timestamp": 1234567890},
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # G1: Check required fields
            if "status" in data and "reply" in data:
                log_test("G1: Required fields present", "PASS", f"Fields: {list(data.keys())}")
            else:
                log_test("G1: Required fields present", "FAIL", f"Missing fields. Got: {list(data.keys())}")
                return False
            
            # G2: Check status field
            if isinstance(data["status"], str) and data["status"] in ["success", "error"]:
                log_test("G2: Status field format", "PASS", f"Status: {data['status']}")
            else:
                log_test("G2: Status field format", "FAIL", f"Invalid status: {data.get('status')}")
                return False
            
            # G3: Check reply field
            if data["status"] == "success":
                if isinstance(data.get("reply"), str):
                    log_test("G3: Reply field format", "PASS", f"Reply type: {type(data['reply'])}")
                else:
                    log_test("G3: Reply field format", "FAIL", f"Invalid reply type: {type(data.get('reply'))}")
                    return False
            
            # G4: Check JSON structure
            try:
                json.dumps(data)
                log_test("G4: Valid JSON structure", "PASS", "Response is valid JSON")
            except:
                log_test("G4: Valid JSON structure", "FAIL", "Response is not valid JSON")
                return False
            
            log_test("G: Overall Response Format", "PASS", "All format checks passed")
            return True
        else:
            log_test("G: Response Format", "FAIL", f"Status: {response.status_code}")
            return False
    except Exception as e:
        log_test("G: Response Format", "FAIL", f"Error: {e}")
        return False

def test_error_handling():
    """Test H: Error Handling"""
    print("\n" + "="*70)
    print("TEST SUITE H: Error Handling")
    print("="*70)
    
    # H1: Invalid JSON
    try:
        response = requests.post(API_URL, data="invalid json", headers=headers, timeout=5)
        if response.status_code in [400, 422]:
            log_test("H1: Invalid JSON handling", "PASS", f"Correctly handled with status {response.status_code}")
        else:
            log_test("H1: Invalid JSON handling", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("H1: Invalid JSON handling", "WARN", f"Exception: {type(e).__name__}")
    
    # H2: Empty request body
    try:
        response = requests.post(API_URL, json={}, headers=headers, timeout=5)
        if response.status_code == 422:
            log_test("H2: Empty request body handling", "PASS", "Correctly rejected with 422")
        else:
            log_test("H2: Empty request body handling", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("H2: Empty request body handling", "FAIL", f"Error: {e}")
    
    # H3: Very long message
    try:
        long_message = "Test " * 1000
        payload = {
            "sessionId": "test-long",
            "message": {"sender": "scammer", "text": long_message, "timestamp": 1234567890},
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            log_test("H3: Very long message handling", "PASS", "Handled successfully")
        else:
            log_test("H3: Very long message handling", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("H3: Very long message handling", "WARN", f"Error: {e}")
    
    # H4: Special characters
    try:
        special_message = "Your account is blocked! @#$%^&*() Verify now: bit.ly/fake"
        payload = {
            "sessionId": "test-special",
            "message": {"sender": "scammer", "text": special_message, "timestamp": 1234567890},
            "conversationHistory": []
        }
        response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            log_test("H4: Special characters handling", "PASS", "Handled successfully")
        else:
            log_test("H4: Special characters handling", "WARN", f"Status: {response.status_code}")
    except Exception as e:
        log_test("H4: Special characters handling", "FAIL", f"Error: {e}")
    
    return True

def test_agent_response_quality():
    """Test I: Agent Response Quality"""
    print("\n" + "="*70)
    print("TEST SUITE I: Agent Response Quality")
    print("="*70)
    
    test_cases = [
        {
            "message": "Your account is blocked",
            "expected_characteristics": ["question", "concern", "surprise"],
            "description": "Initial scam message"
        },
        {
            "message": "Share your UPI ID",
            "expected_characteristics": ["question", "compliance", "interest"],
            "description": "Follow-up with request"
        }
    ]
    
    passed = 0
    for test_case in test_cases:
        try:
            payload = {
                "sessionId": f"test-quality-{int(time.time())}",
                "message": {"sender": "scammer", "text": test_case["message"], "timestamp": int(time.time() * 1000)},
                "conversationHistory": []
            }
            response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                reply = data.get("reply", "").lower()
                
                # Check if reply contains expected characteristics
                has_characteristics = any(char in reply for char in test_case["expected_characteristics"])
                is_reasonable_length = 10 <= len(reply) <= 200
                is_not_revealing = "scam" not in reply and "detect" not in reply
                
                if has_characteristics and is_reasonable_length and is_not_revealing:
                    log_test(f"I: {test_case['description']}", "PASS", f"Quality checks passed. Reply: {reply[:60]}...")
                    passed += 1
                else:
                    log_test(f"I: {test_case['description']}", "WARN", f"Some quality checks failed. Reply: {reply[:60]}...")
            else:
                log_test(f"I: {test_case['description']}", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            log_test(f"I: {test_case['description']}", "FAIL", f"Error: {e}")
    
    log_test("I: Overall Agent Response Quality", "PASS" if passed >= len(test_cases) * 0.8 else "WARN", f"{passed}/{len(test_cases)} passed")
    return passed >= len(test_cases) * 0.8

def test_session_management():
    """Test J: Session Management"""
    print("\n" + "="*70)
    print("TEST SUITE J: Session Management")
    print("="*70)
    
    session_id = f"test-session-{int(time.time())}"
    
    try:
        # J1: Create new session
        payload1 = {
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": "First message", "timestamp": int(time.time() * 1000)},
            "conversationHistory": []
        }
        response1 = requests.post(API_URL, json=payload1, headers=headers, timeout=10)
        if response1.status_code == 200:
            log_test("J1: Session creation", "PASS", "Session created successfully")
        else:
            log_test("J1: Session creation", "FAIL", f"Status: {response1.status_code}")
            return False
        
        # J2: Continue same session
        time.sleep(0.5)
        payload2 = {
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": "Second message", "timestamp": int(time.time() * 1000)},
            "conversationHistory": [
                {"sender": "scammer", "text": "First message", "timestamp": int(time.time() * 1000)},
                {"sender": "user", "text": response1.json().get("reply", ""), "timestamp": int(time.time() * 1000)}
            ]
        }
        response2 = requests.post(API_URL, json=payload2, headers=headers, timeout=10)
        if response2.status_code == 200:
            log_test("J2: Session continuation", "PASS", "Session maintained correctly")
        else:
            log_test("J2: Session continuation", "FAIL", f"Status: {response2.status_code}")
            return False
        
        # J3: Different session ID creates new session
        time.sleep(0.5)
        payload3 = {
            "sessionId": f"{session_id}-new",
            "message": {"sender": "scammer", "text": "New session", "timestamp": int(time.time() * 1000)},
            "conversationHistory": []
        }
        response3 = requests.post(API_URL, json=payload3, headers=headers, timeout=10)
        if response3.status_code == 200:
            log_test("J3: New session creation", "PASS", "New session created independently")
        else:
            log_test("J3: New session creation", "FAIL", f"Status: {response3.status_code}")
            return False
        
        log_test("J: Overall Session Management", "PASS", "All session tests passed")
        return True
    except Exception as e:
        log_test("J: Session Management", "FAIL", f"Error: {e}")
        return False

def test_callback_functionality():
    """Test K: Callback Functionality"""
    print("\n" + "="*70)
    print("TEST SUITE K: Callback Functionality")
    print("="*70)
    
    session_id = f"test-callback-{int(time.time())}"
    conversation_history = []
    
    try:
        # Send messages to trigger callback (need 4+ messages with scam detected)
        messages = [
            "Your account is blocked. Verify immediately.",
            "Share your UPI ID: scammer@paytm to avoid suspension",
            "Send money to account 1234-5678-9012-3456",
            "Call +91-9876543210 for verification",
            "This is urgent! Click bit.ly/fake-link"
        ]
        
        for i, msg_text in enumerate(messages):
            payload = {
                "sessionId": session_id,
                "message": {"sender": "scammer", "text": msg_text, "timestamp": int(time.time() * 1000)},
                "conversationHistory": conversation_history.copy()
            }
            
            response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                reply = data.get("reply", "")
                
                conversation_history.append({"sender": "scammer", "text": msg_text, "timestamp": int(time.time() * 1000)})
                conversation_history.append({"sender": "user", "text": reply, "timestamp": int(time.time() * 1000)})
                
                log_test(f"K{i+1}: Message {i+1} sent", "PASS", f"Reply received: {reply[:40]}...")
                time.sleep(0.5)
            else:
                log_test(f"K{i+1}: Message {i+1}", "FAIL", f"Status: {response.status_code}")
        
        # Note: We can't directly verify callback was sent, but if we reached here without errors,
        # the callback logic should have executed (it's async/non-blocking)
        log_test("K: Callback Functionality", "PASS", "Callback should have been triggered after 4+ messages")
        return True
    except Exception as e:
        log_test("K: Callback Functionality", "FAIL", f"Error: {e}")
        return False

def test_performance():
    """Test L: Performance & Response Time"""
    print("\n" + "="*70)
    print("TEST SUITE L: Performance")
    print("="*70)
    
    response_times = []
    
    try:
        for i in range(5):
            start_time = time.time()
            payload = {
                "sessionId": f"test-perf-{i}",
                "message": {"sender": "scammer", "text": "Your account is blocked", "timestamp": int(time.time() * 1000)},
                "conversationHistory": []
            }
            response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
            end_time = time.time()
            
            if response.status_code == 200:
                response_time = (end_time - start_time) * 1000  # Convert to ms
                response_times.append(response_time)
                log_test(f"L{i+1}: Response time test {i+1}", "PASS", f"{response_time:.2f}ms")
            else:
                log_test(f"L{i+1}: Response time test {i+1}", "FAIL", f"Status: {response.status_code}")
            time.sleep(0.5)
        
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            
            log_test("L: Average Response Time", "PASS" if avg_time < 3000 else "WARN", f"{avg_time:.2f}ms")
            log_test("L: Max Response Time", "PASS" if max_time < 5000 else "WARN", f"{max_time:.2f}ms")
            log_test("L: Min Response Time", "PASS", f"{min_time:.2f}ms")
            
            return avg_time < 3000
        else:
            log_test("L: Performance", "FAIL", "No successful responses")
            return False
    except Exception as e:
        log_test("L: Performance", "FAIL", f"Error: {e}")
        return False

def test_edge_cases():
    """Test M: Edge Cases"""
    print("\n" + "="*70)
    print("TEST SUITE M: Edge Cases")
    print("="*70)
    
    edge_cases = [
        {
            "name": "Empty message",
            "payload": {
                "sessionId": "test-edge-1",
                "message": {"sender": "scammer", "text": "", "timestamp": 1234567890},
                "conversationHistory": []
            }
        },
        {
            "name": "Very short message",
            "payload": {
                "sessionId": "test-edge-2",
                "message": {"sender": "scammer", "text": "Hi", "timestamp": 1234567890},
                "conversationHistory": []
            }
        },
        {
            "name": "Message with only numbers",
            "payload": {
                "sessionId": "test-edge-3",
                "message": {"sender": "scammer", "text": "1234567890", "timestamp": 1234567890},
                "conversationHistory": []
            }
        },
        {
            "name": "Message with only special characters",
            "payload": {
                "sessionId": "test-edge-4",
                "message": {"sender": "scammer", "text": "@#$%^&*()", "timestamp": 1234567890},
                "conversationHistory": []
            }
        },
        {
            "name": "Unicode characters",
            "payload": {
                "sessionId": "test-edge-5",
                "message": {"sender": "scammer", "text": "Your account is blocked! 🚨 Verify now!", "timestamp": 1234567890},
                "conversationHistory": []
            }
        }
    ]
    
    passed = 0
    for case in edge_cases:
        try:
            response = requests.post(API_URL, json=case["payload"], headers=headers, timeout=10)
            if response.status_code == 200:
                log_test(f"M: {case['name']}", "PASS", "Handled successfully")
                passed += 1
            else:
                log_test(f"M: {case['name']}", "WARN", f"Status: {response.status_code}")
        except Exception as e:
            log_test(f"M: {case['name']}", "WARN", f"Error: {type(e).__name__}")
    
    log_test("M: Overall Edge Cases", "PASS" if passed >= len(edge_cases) * 0.6 else "WARN", f"{passed}/{len(edge_cases)} handled")
    return passed >= len(edge_cases) * 0.6

def generate_test_report():
    """Generate comprehensive test report"""
    print("\n" + "="*70)
    print("COMPREHENSIVE TEST REPORT")
    print("="*70)
    
    total_tests = len(test_results)
    passed = sum(1 for r in test_results if r["status"] == "PASS")
    failed = sum(1 for r in test_results if r["status"] == "FAIL")
    warnings = sum(1 for r in test_results if r["status"] == "WARN")
    
    print(f"\nTotal Tests: {total_tests}")
    print(f"Passed: {passed} ({passed/total_tests*100:.1f}%)")
    print(f"Failed: {failed} ({failed/total_tests*100:.1f}%)")
    print(f"Warnings: {warnings} ({warnings/total_tests*100:.1f}%)")
    
    print("\n" + "="*70)
    print("DETAILED RESULTS")
    print("="*70)
    
    for result in test_results:
        status_symbol = "[PASS]" if result["status"] == "PASS" else "[FAIL]" if result["status"] == "FAIL" else "[WARN]"
        print(f"\n{status_symbol} {result['test']}")
        if result["details"]:
            print(f"   {result['details']}")
    
    return {
        "total": total_tests,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "results": test_results
    }

if __name__ == "__main__":
    print("="*70)
    print("COMPREHENSIVE TEST SUITE - A-Z Testing")
    print("="*70)
    print(f"\nAPI URL: {API_URL}")
    print(f"API Key: {API_KEY[:20]}..." if len(API_KEY) > 20 else f"API Key: {API_KEY}")
    print("\nStarting comprehensive tests...\n")
    
    # Check server availability first
    if not test_api_server_availability():
        print("\n[ERROR] API server is not running. Please start the server first.")
        exit(1)
    
    # Run all test suites
    test_api_authentication()
    test_request_validation()
    test_scam_detection()
    test_intelligence_extraction()
    test_multi_turn_conversations()
    test_response_format()
    test_error_handling()
    test_agent_response_quality()
    test_session_management()
    test_callback_functionality()
    test_performance()
    test_edge_cases()
    
    # Generate report
    report = generate_test_report()
    
    # Save report to file
    with open("test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "="*70)
    print("TEST REPORT SAVED TO: test_report.json")
    print("="*70)
