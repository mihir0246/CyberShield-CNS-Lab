import pytest
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybershield.app import create_app
from cybershield.config import TestingConfig, BASE_DIR
from cybershield.extensions import db


@pytest.fixture
def app():
    """Create and configure a clean Flask application instance for testing."""
    test_app = create_app(TestingConfig)
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """A test client for making simulated HTTP requests to the app."""
    return app.test_client()


@pytest.fixture
def sample_pcap_path():
    """Returns absolute path to sample PCAP file."""
    return str(BASE_DIR / "samples" / "sample_capture.pcap")


@pytest.fixture
def sample_nmap_xml_path():
    """Returns absolute path to sample Nmap XML scan output."""
    return str(BASE_DIR / "samples" / "sample_nmap.xml")


@pytest.fixture
def sample_snort_log_path():
    """Returns absolute path to sample Snort alert log."""
    return str(BASE_DIR / "samples" / "sample_snort.log")
