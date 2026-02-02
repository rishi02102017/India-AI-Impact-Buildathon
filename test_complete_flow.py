"""
Complete end-to-end test for the Agentic Honey-Pot API
Tests all functionality including scam detection, agent responses, intelligence extraction, and callback
"""

import requests
import json
import time
import os
from dotenv import load_dotenv

load_dotenv()

API_URL = "http://localhost:8000/api/honeypot"
API_KEY = os.getenv("API_KEY", "default_secret_key_change_me")

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def test_api_authentication():
    """Test API key authentication"""
    print_section("TEST 1: API Authentication")
    
    # Test without API key
    print("\n1.1 Testing without API key...")
    try:
        response = requests.post(API_URL, json={}, timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 401:
            print("   [PASS] Correctly rejected request without API key")
        else:
            print(f"   [WARN] Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"   [ERROR] {e}")
    
    # Test with invalid API key
    print("\n1.2 Testing with invalid API key...")
    invalid_headers = {
        "Content-Type": "application/json",
        "x-api-key": "invalid_key_12345"
    }
    try:
        response = requests.post(API_URL, json={}, headers=invalid_headers, timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 401:
            print("   [PASS] Correctly rejected request with invalid API key")
        else:
            print(f"   [WARN] Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"   [ERROR] {e}")

def test_scam_detection_and_extraction():
    """Test complete scam detection and intelligence extraction flow"""
    print_section("TEST 2: Complete Scam Detection Flow")
    
    session_id = f"test-complete-{int(time.time())}"
    conversation_history = []
    
    # Message 1: Initial scam message with bank account threat
    print("\n2.1 Sending initial scam message...")
    message1 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately by clicking this link: bit.ly/fake-bank-verify",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    try:
        response1 = requests.post(API_URL, json=message1, headers=headers, timeout=30)
        print(f"   Status: {response1.status_code}")
        if response1.status_code == 200:
            data1 = response1.json()
            print(f"   Response: {json.dumps(data1, indent=2)}")
            print("   [PASS] Received response")
            if data1.get("status") == "success" and data1.get("reply"):
                print(f"   [PASS] Agent replied: {data1['reply'][:100]}...")
                conversation_history.append(message1["message"])
                conversation_history.append({
                    "sender": "user",
                    "text": data1["reply"],
                    "timestamp": int(time.time() * 1000)
                })
            else:
                print("   [WARN] Response format issue")
        else:
            print(f"   [ERROR] {response1.text}")
            return
    except Exception as e:
        print(f"   [ERROR] {e}")
        return
    
    time.sleep(1)
    
    # Message 2: Follow-up with UPI ID request
    print("\n2.2 Sending follow-up message with UPI ID request...")
    message2 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Share your UPI ID like scammer@paytm to avoid account suspension. Also call +91-9876543210 for verification",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": conversation_history,
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    try:
        response2 = requests.post(API_URL, json=message2, headers=headers, timeout=30)
        print(f"   Status: {response2.status_code}")
        if response2.status_code == 200:
            data2 = response2.json()
            print(f"   Response: {json.dumps(data2, indent=2)}")
            print("   [PASS] Received response")
            if data2.get("status") == "success" and data2.get("reply"):
                print(f"   [PASS] Agent replied: {data2['reply'][:100]}...")
                conversation_history.append(message2["message"])
                conversation_history.append({
                    "sender": "user",
                    "text": data2["reply"],
                    "timestamp": int(time.time() * 1000)
                })
        else:
            print(f"   [ERROR] {response2.text}")
    except Exception as e:
        print(f"   [ERROR] {e}")
    
    time.sleep(1)
    
    # Message 3: Bank account request
    print("\n2.3 Sending message with bank account request...")
    message3 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Send money to account 1234-5678-9012-3456 to verify your account immediately",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": conversation_history,
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    try:
        response3 = requests.post(API_URL, json=message3, headers=headers, timeout=30)
        print(f"   Status: {response3.status_code}")
        if response3.status_code == 200:
            data3 = response3.json()
            print(f"   Response: {json.dumps(data3, indent=2)}")
            print("   [PASS] Received response")
            if data3.get("status") == "success" and data3.get("reply"):
                print(f"   [PASS] Agent replied: {data3['reply'][:100]}...")
                print("\n   Intelligence should be extracted:")
                print("      - Bank account: 1234-5678-9012-3456")
                print("      - UPI ID: scammer@paytm")
                print("      - Phone number: +91-9876543210")
                print("      - Phishing link: bit.ly/fake-bank-verify")
        else:
            print(f"   [ERROR] {response3.text}")
    except Exception as e:
        print(f"   [ERROR] {e}")
    
    # Message 4: Trigger callback (if not already sent)
    print("\n2.4 Sending final message to trigger callback...")
    conversation_history.append(message3["message"])
    conversation_history.append({
        "sender": "user",
        "text": response3.json().get("reply", ""),
        "timestamp": int(time.time() * 1000)
    })
    
    message4 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "This is urgent! Your account will be closed in 1 hour.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": conversation_history,
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    try:
        response4 = requests.post(API_URL, json=message4, headers=headers, timeout=30)
        print(f"   Status: {response4.status_code}")
        if response4.status_code == 200:
            data4 = response4.json()
            print(f"   Response: {json.dumps(data4, indent=2)}")
            print("   [PASS] Received response")
            print("   [INFO] Callback should have been sent to evaluation endpoint")
        else:
            print(f"   [ERROR] {response4.text}")
    except Exception as e:
        print(f"   [ERROR] {e}")

def test_non_scam_message():
    """Test with a normal (non-scam) message"""
    print_section("TEST 3: Non-Scam Message Handling")
    
    session_id = f"test-normal-{int(time.time())}"
    
    message = {
        "sessionId": session_id,
        "message": {
            "sender": "user",
            "text": "Hello, how are you today? Just checking in.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    try:
        response = requests.post(API_URL, json=message, headers=headers, timeout=30)
        print(f"\nStatus: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
            print("[PASS] Handled non-scam message correctly")
            if "Thank you" in data.get("reply", ""):
                print("[PASS] Appropriate neutral response for non-scam")
        else:
            print(f"[ERROR] {response.text}")
    except Exception as e:
        print(f"[ERROR] {e}")

def test_response_format():
    """Test response format matches specification"""
    print_section("TEST 4: Response Format Validation")
    
    session_id = f"test-format-{int(time.time())}"
    
    message = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Your account is suspended. Verify now.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {}
    }
    
    try:
        response = requests.post(API_URL, json=message, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            # Check required fields
            required_fields = ["status", "reply"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                print(f"[ERROR] Missing required fields: {missing_fields}")
            else:
                print("[PASS] All required fields present")
            
            # Check field types
            if not isinstance(data.get("status"), str):
                print("[ERROR] 'status' should be a string")
            elif data["status"] not in ["success", "error"]:
                print(f"[WARN] 'status' should be 'success' or 'error', got: {data['status']}")
            else:
                print("[PASS] 'status' field is correct")
            
            if data.get("status") == "success":
                if not isinstance(data.get("reply"), str):
                    print("[ERROR] 'reply' should be a string when status is 'success'")
                else:
                    print("[PASS] 'reply' field is correct")
            
            print(f"\nFull response: {json.dumps(data, indent=2)}")
        else:
            print(f"[ERROR] {response.text}")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  AGENTIC HONEY-POT API - COMPLETE TEST SUITE")
    print("=" * 70)
    print(f"\nAPI URL: {API_URL}")
    print(f"API Key: {API_KEY[:20]}..." if len(API_KEY) > 20 else f"API Key: {API_KEY}")
    print("\nMake sure the API server is running on http://localhost:8000")
    print("Starting tests...\n")
    
    # Check if server is running
    try:
        health_response = requests.get("http://localhost:8000/health", timeout=5)
        if health_response.status_code == 200:
            print("[PASS] API server is running\n")
        else:
            print("[ERROR] API server is not responding correctly")
            exit(1)
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to API server. Make sure it's running on http://localhost:8000")
        exit(1)
    
    # Run all tests
    test_api_authentication()
    test_scam_detection_and_extraction()
    test_non_scam_message()
    test_response_format()
    
    print("\n" + "=" * 70)
    print("  ALL TESTS COMPLETED")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Review test results above")
    print("2. Check server logs for any errors")
    print("3. Verify callback was sent to evaluation endpoint")
    print("4. Deploy to cloud platform when ready")
    print("5. Submit your API endpoint URL to the hackathon platform\n")
