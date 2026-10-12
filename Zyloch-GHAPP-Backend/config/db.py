"""
MongoDB Database Configuration
Handles connection and database instance management.
"""

import os
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import logging

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """Singleton class to manage MongoDB connection"""
    
    _instance = None
    _client = None
    _database = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
        return cls._instance
    
    def connect(self, retries: int = 5, delay: int = 5000) -> Database:
        """
        Connect to MongoDB with retry logic
        
        Args:
            retries: Number of connection attempts
            delay: Delay between retries in milliseconds
            
        Returns:
            Database instance
            
        Raises:
            ConnectionFailure: If connection fails after all retries
        """
        if self._database is not None:
            return self._database
            
        mongodb_url = os.getenv("MONGODB_URL", "mongodb://admin:password123@localhost:27017/admin")
        database_name = os.getenv("DATABASE_NAME", "policy_scanner")
        
        if not mongodb_url:
            raise ValueError("MONGODB_URL not defined in environment")
        
        for attempt in range(retries):
            try:
                logger.info(f"Attempting to connect to MongoDB (attempt {attempt + 1}/{retries})")
                
                self._client = MongoClient(
                    mongodb_url,
                    serverSelectionTimeoutMS=delay
                )
                
                # Test the connection
                self._client.admin.command('ping')
                self._database = self._client[database_name]
                
                logger.info(f"Successfully connected to MongoDB database: {database_name}")
                return self._database
                
            except (ConnectionFailure, ServerSelectionTimeoutError) as e:
                logger.warning(f"MongoDB connection attempt {attempt + 1} failed: {e}")
                
                if attempt == retries - 1:
                    error_msg = f"MongoDB connection failed after {retries} attempts"
                    logger.error(error_msg)
                    raise ConnectionFailure(error_msg) from e
                    
                # Wait before retrying (using simple blocking sleep for simplicity)
                import time
                time.sleep(delay / 1000)
        
        raise ConnectionFailure("Failed to connect to MongoDB")
    
    def get_database(self) -> Database:
        """
        Get the database instance, connecting if necessary
        
        Returns:
            Database instance
        """
        if self._database is None:
            return self.connect()
        return self._database
    
    def close(self):
        """Close the MongoDB connection"""
        if self._client is not None:
            self._client.close()
            self._client = None
            self._database = None
            logger.info("MongoDB connection closed")


# Global database connection instance
_db_connection = DatabaseConnection()


def get_database(retries: int = 5, delay: int = 5000) -> Database:
    """
    Get MongoDB database instance with connection handling
    
    Args:
        retries: Number of connection attempts
        delay: Delay between retries in milliseconds
        
    Returns:
        Database instance
    """
    return _db_connection.connect(retries=retries, delay=delay)


def close_database():
    """Close the database connection"""
    _db_connection.close()


def get_main_database(retries: int = 5, delay: int = 5000) -> Database:
    """Return the *main* application database (the one used by Zyloch-Backend).

    Scan configurations (enabled/disabled scans per org) are stored in the
    ``organizations`` collection inside this database.  The name is controlled
    by the ``MAIN_DATABASE_NAME`` env-var (default ``zyloch``).
    """
    # Reuse the same MongoClient created by the singleton, just switch the db.
    _db_connection.connect(retries=retries, delay=delay)   # ensure connected
    main_db_name = os.getenv("MAIN_DATABASE_NAME", "zyloch")
    return _db_connection._client[main_db_name]
