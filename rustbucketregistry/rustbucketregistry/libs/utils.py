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
    import re
    # Convert to lowercase
    name = name.lower()
    # Replace spaces and underscores with hyphens
    name = name.replace(' ', '-').replace('_', '-')

    # For Test@Registry! -> test@registry! (already lowercase)
    # Expected: test-registry

    # Insert hyphens at the location of special characters
    name = re.sub(r'[^a-z0-9-]+', '-', name)

    # Remove multiple consecutive hyphens if any
    name = re.sub(r'-+', '-', name)

    # Remove leading and trailing hyphens
    name = name.strip('-')

    return name


def validate_registry_url(url):
    """
    Validate that a registry URL is properly formatted.

    Args:
        url (str): The URL to validate

    Returns:
        bool: True if valid

    Raises:
        ValidationError: If the URL is invalid
    """
    from django.core.exceptions import ValidationError

    if not url:
        raise ValidationError("URL cannot be empty")

    if not (url.startswith('http://') or url.startswith('https://')):
        raise ValidationError("URL must start with http:// or https://")

    # Missing domain check
    if url in ('http://', 'https://'):
        raise ValidationError("URL must include a domain")

    return True