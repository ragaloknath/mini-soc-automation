"""Centralized logging configuration."""
import logging
from config import LOG_FILE

def get_logger(name: str) -> logging.Logger:
    """
    Configures and returns a logger instance.
    
    Args:
        name (str): Name of the logger module.
        
    Returns:
        logging.Logger: Configured logger object.
    """
    logger = logging.getLogger(name)
    
    # Prevent adding handlers multiple times if instantiated multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # File Handler
        file_handler = logging.FileHandler(LOG_FILE)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        
        # Console Handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
    return logger