#!/usr/bin/env python3
"""
Demo script to test the fraud detection API with various scenarios
"""
import requests
import json

API_URL = "http://localhost:8000/api/v1/analyze"

def test_scenario(name, email, ip, user_agent="Mozilla/5.0"):
    """Test a single scenario and print results"""
    print(f"\n{'='*60}")
    print(f"Scenario: {name}")
    print(f"{'='*60}")
    print(f"Email: {email}")
    print(f"IP: {ip}")
    
    payload = {
        "email": email,
        "ip_address": ip,
        "user_agent": user_agent
    }
    
    try:
        response = requests.post(API_URL, json=payload)
        result = response.json()
        
        print(f"\nRisk Score: {result['risk_summary']['score']}")
        print(f"Level: {result['risk_summary']['level']}")
        print(f"Action: {result['risk_summary']['action']}")
        print(f"\nKey Signals:")
        
        signals = result['signals']
        for key, value in signals.items():
            if value and value not in [False, None, 0, 0.0]:
                print(f"  • {key}: {value}")
        
        print(f"\nNormalized Email: {result['normalized_email']}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("🔍 Fraud Detection API - Test Scenarios")
    
    # Scenario 1: Clean user
    test_scenario(
        "Clean User",
        "john.doe@gmail.com",
        "192.168.1.10"
    )
    
    # Scenario 2: Sequential pattern
    test_scenario(
        "Sequential Pattern (Suspicious)",
        "user1@example.com",
        "192.168.1.10"
    )
    
    # Scenario 3: Number suffix pattern
    test_scenario(
        "Number Suffix Pattern",
        "testuser123@yahoo.com",
        "192.168.1.10"
    )
    
    # Scenario 4: Email alias
    test_scenario(
        "Email Alias",
        "john.doe+spam@gmail.com",
        "192.168.1.10"
    )
    
    # Scenario 5: Disposable email
    test_scenario(
        "Disposable Email (HIGH RISK)",
        "test@mailinator.com",
        "192.168.1.10"
    )
    
    # Scenario 6: High entropy
    test_scenario(
        "High Entropy Email",
        "a8f3k2ds9x@example.com",
        "192.168.1.10"
    )
    
    # Scenario 7: Multiple suspicious signals
    test_scenario(
        "Multiple Red Flags",
        "user5@newdomain.xyz",
        "8.8.8.8"  # Public IP for VPN check
    )
    
    print(f"\n{'='*60}")
    print("✅ All scenarios tested!")
    print(f"{'='*60}\n")
