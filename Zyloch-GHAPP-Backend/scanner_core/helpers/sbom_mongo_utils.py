"""
MongoDB utility module for SBOM scanner.
Handles MongoDB connection and package data retrieval from separate SBOM database.
"""

import os
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import (
    ConnectionFailure,
    NetworkTimeout,
    ServerSelectionTimeoutError,
)
from typing import Optional, Dict, Any
import logging

# User-facing message for API / scan responses (keep in sync with sbom_scanner fail-fast path)
SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE = (
    "SBOM MongoDB connection failed. "
    "Verify intel_repo_url and SBOM_DATABASE_NAME, and that the host is reachable."
)


class SBOMMongoConnectionError(Exception):
    """SBOM Intel MongoDB is unreachable or server selection timed out."""


_CONNECTIVITY_ERRORS = (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout)

# Use the same logger as scanners for consistency
try:
    from scanner_core.logging_config import get_scanner_logger
    logger = get_scanner_logger()
except ImportError:
    # Fallback to standard logging if scanner logger not available
    logger = logging.getLogger("sbom_mongo")
    logger.setLevel(logging.INFO)

# MongoDB Configuration for SBOM package metadata (intel_repo_url / SBOM_MONGODB_URL from env)
SBOM_MONGO_URI = os.getenv("intel_repo_url", os.getenv("SBOM_MONGODB_URL", "mongodb://admin:changeme123@100.118.172.97:27017/IntelDB?authSource=IntelDB"))
SBOM_DB_NAME = os.getenv("SBOM_DATABASE_NAME", "IntelDB")
_DEFAULT_SBOM_TIMEOUT_MS = int(os.getenv("SBOM_MONGODB_SERVER_SELECTION_TIMEOUT_MS", "10000"))


def _redact_mongo_uri(uri: str) -> str:
    """Avoid logging credentials from MongoDB URIs."""
    if "@" not in uri or "://" not in uri:
        return uri
    scheme, rest = uri.split("://", 1)
    if "@" not in rest:
        return uri
    hostpart = rest.split("@", 1)[1]
    return f"{scheme}://***:***@{hostpart}"

# Collection mapping for different package managers
COLLECTION_MAP = {
    "pypi": "Updated_pypi_metadata",
    "npm": "Updated_npm_metadata",
    "go": "Updated_go_metadata",
    "maven": "Updated_maven_metadata",
    "gradle": "Updated_maven_metadata",  
}

# Singleton MongoDB client for SBOM database
_sbom_mongo_client: Optional[MongoClient] = None
_sbom_db: Optional[Database] = None


def ensure_sbom_mongo_connection() -> None:
    """
    Ping SBOM MongoDB and validate access to the configured database.
    Raises SBOMMongoConnectionError if the cluster cannot be reached.
    """
    try:
        client = get_sbom_mongo_client()
        client.admin.command("ping")
        db = client[SBOM_DB_NAME]
        db.list_collection_names()
    except SBOMMongoConnectionError:
        raise
    except _CONNECTIVITY_ERRORS as e:
        close_sbom_connection()
        raise SBOMMongoConnectionError(SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE) from e


def get_sbom_mongo_client() -> MongoClient:
    global _sbom_mongo_client, _sbom_db
    if _sbom_mongo_client is None:
        client: Optional[MongoClient] = None
        safe_uri = _redact_mongo_uri(SBOM_MONGO_URI)
        try:
            logger.info(
                "Attempting to connect to SBOM MongoDB: %s, Database: %s (serverSelectionTimeoutMS=%s)",
                safe_uri,
                SBOM_DB_NAME,
                _DEFAULT_SBOM_TIMEOUT_MS,
            )
            client = MongoClient(
                SBOM_MONGO_URI,
                serverSelectionTimeoutMS=_DEFAULT_SBOM_TIMEOUT_MS,
                connectTimeoutMS=_DEFAULT_SBOM_TIMEOUT_MS,
            )
            client.admin.command("ping")
            db = client[SBOM_DB_NAME]
            collections = db.list_collection_names()
            logger.info(
                "Successfully connected to SBOM MongoDB: %s, collections: %s",
                SBOM_DB_NAME,
                len(collections),
            )
            if collections:
                logger.info("Available collections: %s", collections[:10])
            print(f"[SBOM] Connected to MongoDB: {SBOM_DB_NAME}, Collections: {len(collections)}")
            _sbom_mongo_client = client
            client = None
        except _CONNECTIVITY_ERRORS as e:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            _sbom_mongo_client = None
            _sbom_db = None
            error_msg = (
                f"Failed to connect to SBOM MongoDB ({safe_uri}, db={SBOM_DB_NAME}): {e}. "
                "Check intel_repo_url / SBOM_DATABASE_NAME and network (Kubernetes *.svc.cluster.local "
                "names only resolve inside the cluster)."
            )
            logger.error(error_msg, exc_info=True)
            print(f"[SBOM ERROR] {error_msg}")
            raise SBOMMongoConnectionError(SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE) from e
        except Exception as e:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            _sbom_mongo_client = None
            _sbom_db = None
            error_msg = f"Unexpected error connecting to SBOM MongoDB ({safe_uri}): {e}"
            logger.error(error_msg, exc_info=True)
            print(f"[SBOM ERROR] {error_msg}")
            raise SBOMMongoConnectionError(SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE) from e
    return _sbom_mongo_client


def get_sbom_database() -> Database:
    """
    Get or create database instance for SBOM package metadata.
    Returns:
        pymongo.database.Database: Database instance
    """
    global _sbom_db
    if _sbom_db is None:
        client = get_sbom_mongo_client()
        _sbom_db = client[SBOM_DB_NAME]
    return _sbom_db


def get_collection_for_manager(manager: str) -> Optional[Any]:
    """
    Get MongoDB collection for a given package manager.
    Args:
        manager: Package manager name (pypi, npm, go, maven, gradle)
    Returns:
        pymongo.collection.Collection: MongoDB collection or None if manager not found
    """
    collection_name = COLLECTION_MAP.get(manager.lower())
    if collection_name is None:
        return None
    
    db = get_sbom_database()
    return db[collection_name]


def get_package_by_name(manager: str, package_name: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve package data from MongoDB by manager and package name.
    Args:
        manager: Package manager name (pypi, npm, go, maven, gradle)
        package_name: Package name/identifier
    Returns:
        Dict with structure:
        - If SHA exists in object: {"object": {...}, "sha": sha_from_object}
        - If SHA doesn't exist in object: {"object": {...}, "sha": None} (will be shown as "Unknown")
        - Returns None if package not found
    """
    try:
        collection = get_collection_for_manager(manager)
        if collection is None:
            logger.warning(f"Collection not found for manager: {manager}")
            return None
        
        logger.debug(f"Querying MongoDB for package: {manager}/{package_name}")

        document = collection.find_one({"package_name": package_name})

        if document:
            if "object" in document:
                package_data = document["object"]
                sha_value = None

                if isinstance(package_data, dict):
                    sha_value = package_data.get("sha") or package_data.get("sha256") or package_data.get("sha1")

                logger.debug(f"Found document for {manager}/{package_name}")

                return {
                    "object": package_data,
                    "sha": sha_value
                }
            else:
                logger.warning(f"Document found for {manager}/{package_name} but missing 'object' field")
                return None
        else:
            return None
    except SBOMMongoConnectionError:
        raise
    except _CONNECTIVITY_ERRORS as e:
        logger.error(
            "SBOM MongoDB connectivity error for %s/%s: %s", manager, package_name, e, exc_info=True
        )
        raise SBOMMongoConnectionError(SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE) from e
    except Exception as e:
        logger.error(f"Error querying SBOM MongoDB for {manager}/{package_name}: {e}", exc_info=True)
        return None


def close_sbom_connection():
    """
    Close SBOM MongoDB connection. Useful for cleanup.
    """
    global _sbom_mongo_client, _sbom_db
    if _sbom_mongo_client:
        _sbom_mongo_client.close()
        _sbom_mongo_client = None
        _sbom_db = None
        logger.info("SBOM MongoDB connection closed")

