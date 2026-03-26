#!/usr/bin/env python3
"""
Generate a secure SECRET_KEY for your Flask application
"""
import secrets

def generate_secret_key(length=32):
    """Generate a secure random secret key"""
    return secrets.token_urlsafe(length)

if __name__ == "__main__":
    print("=== Secret Key Generator ===")
    print("Generated secret keys:")
    print()

    # Generate different lengths
    for length in [32, 48, 64]:
        key = generate_secret_key(length)
        print(f"Length {length}: {key}")
        print()

    print("\n💡 Tips:")
    print("- Copy one of the keys above to your .env file")
    print("- Use at least 32 characters for production")
    print("- Mix uppercase, lowercase, numbers, and symbols")
    print("- Generate a new key every 3-6 months for security")