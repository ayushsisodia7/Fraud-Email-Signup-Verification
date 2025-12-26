from email_validator import validate_email, EmailNotValidError

def validate_email_syntax(email: str) -> bool:
    """
    Validates email syntax using email-validator.
    Returns True if valid, raises EmailNotValidError if invalid.
    """
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError as e:
        # In a real scenario, we might want to log this or propagate the specific error
        return False
