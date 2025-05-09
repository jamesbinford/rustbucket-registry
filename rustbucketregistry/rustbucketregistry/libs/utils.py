"""
Utility functions for the RustBucket Registry application.
"""

def format_registry_name(name):
    """
    Format a registry name according to application standards.
    
    Args:
        name (str): The registry name to format
        
    Returns:
        str: The formatted registry name
    """
    return name.lower().replace(' ', '-')


def validate_registry_url(url):
    """
    Validate that a registry URL is properly formatted.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Basic validation for demonstration
    return url and (url.startswith('http://') or url.startswith('https://'))