"""
Test script for the Agentic Honey-Pot API
Run this to test your API locally
"""

import requests
import json
import time

API_URL = "http://localhost:8000/api/honeypot"
API_KEY = "your_secret_api_key_here"  # Change this to match your .env

headers = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}


def test_scam_detection():
    """Test the honeypot with a scam message"""
    print("=" * 60)
    print("Testing Scam Detection")
    print("=" * 60)
    
    session_id = f"test-session-{int(time.time())}"
    
    # First message - scam detection
    payload1 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately by clicking this link: bit.ly/fake-bank",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    print(f"\n1. Sending first message (scam)...")
    print(f"   Message: {payload1['message']['text']}")
    
    response1 = requests.post(API_URL, json=payload1, headers=headers)
    print(f"   Status: {response1.status_code}")
    print(f"   Response: {json.dumps(response1.json(), indent=2)}")
    
    if response1.status_code == 200:
        reply1 = response1.json().get("reply")
        
        # Second message - follow-up
        time.sleep(1)
        payload2 = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Share your UPI ID: scammer@paytm to avoid account suspension. Also call +91-9876543210",
                "timestamp": int(time.time() * 1000)
            },
            "conversationHistory": [
                {
                    "sender": "scammer",
                    "text": payload1["message"]["text"],
                    "timestamp": payload1["message"]["timestamp"]
                },
                {
                    "sender": "user",
                    "text": reply1,
                    "timestamp": int(time.time() * 1000)
                }
            ],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        print(f"\n2. Sending follow-up message...")
        print(f"   Message: {payload2['message']['text']}")
        
        response2 = requests.post(API_URL, json=payload2, headers=headers)
        print(f"   Status: {response2.status_code}")
        print(f"   Response: {json.dumps(response2.json(), indent=2)}")
        
        # Third message - extract more info
        if response2.status_code == 200:
            reply2 = response2.json().get("reply")
            time.sleep(1)
            
            payload3 = {
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Send money to account 1234-5678-9012-3456 to verify your account",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [
                    {
                        "sender": "scammer",
                        "text": payload1["message"]["text"],
                        "timestamp": payload1["message"]["timestamp"]
                    },
                    {
                        "sender": "user",
                        "text": reply1,
                        "timestamp": int(time.time() * 1000)
                    },
                    {
                        "sender": "scammer",
                        "text": payload2["message"]["text"],
                        "timestamp": payload2["message"]["timestamp"]
                    },
                    {
                        "sender": "user",
                        "text": reply2,
                        "timestamp": int(time.time() * 1000)
                    }
                ],
                "metadata": {
                    "channel": "SMS",
                    "language": "English",
                    "locale": "IN"
                }
            }
            
            print(f"\n3. Sending third message...")
            print(f"   Message: {payload3['message']['text']}")
            
            response3 = requests.post(API_URL, json=payload3, headers=headers)
            print(f"   Status: {response3.status_code}")
            print(f"   Response: {json.dumps(response3.json(), indent=2)}")
            
            print(f"\n[PASS] Test completed! Check if callback was sent to evaluation endpoint.")
    else:
        print(f"[ERROR] {response1.text}")


def test_non_scam():
    """Test with a non-scam message"""
    print("\n" + "=" * 60)
    print("Testing Non-Scam Message")
    print("=" * 60)
    
    session_id = f"test-normal-{int(time.time())}"
    
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "user",
            "text": "Hello, how are you today?",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    print(f"\nSending normal message...")
    print(f"   Message: {payload['message']['text']}")
    
    response = requests.post(API_URL, json=payload, headers=headers)
    print(f"   Status: {response.status_code}")
    print(f"   Response: {json.dumps(response.json(), indent=2)}")


def test_invalid_api_key():
    """Test with invalid API key"""
    print("\n" + "=" * 60)
    print("Testing Invalid API Key")
    print("=" * 60)
    
    invalid_headers = {
        "Content-Type": "application/json",
        "x-api-key": "invalid_key"
    }
    
    payload = {
        "sessionId": "test-invalid",
        "message": {
            "sender": "scammer",
            "text": "Test message",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {}
    }
    
    print(f"\nSending request with invalid API key...")
    
    response = requests.post(API_URL, json=payload, headers=invalid_headers)
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.text}")


if __name__ == "__main__":
    print("Agentic Honey-Pot API Test Suite")
    print("Make sure the API server is running on http://localhost:8000")
    print(f"Using API Key: {API_KEY}")
    print("\nPress Enter to start tests...")
    input()
    
    try:
        # Test health endpoint
        health_response = requests.get("http://localhost:8000/health")
        if health_response.status_code == 200:
            print("[PASS] API server is running\n")
        else:
            print("[ERROR] API server is not responding correctly")
            exit(1)
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to API server. Make sure it's running on http://localhost:8000")
        exit(1)
    
    # Run tests
    test_scam_detection()
    test_non_scam()
    test_invalid_api_key()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)
