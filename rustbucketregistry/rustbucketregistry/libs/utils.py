"""Utility functions for the RustBucket Registry application.

This module contains utility functions for formatting and processing
data used throughout the RustBucket Registry application.
"""

def format_registry_name(name):
    """Formats a registry name according to application standards.
    
    Args:
        name: The registry name to format.
        
    Returns:
        The formatted registry name.
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