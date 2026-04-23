from urllib.parse import urlparse


def is_https(url):
    """
    Check if a URL uses HTTPS protocol.
    
    Args:
        url (str): The URL to check
        
    Returns:
        bool: True if the URL uses HTTPS, False otherwise
    """
    if not url:
        return False
    
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme.lower() == 'https'
    except Exception:
        return False
