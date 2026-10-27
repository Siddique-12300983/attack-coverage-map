"""Shared paths for the test suite."""

import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
FIXTURES = os.path.join(TESTS_DIR, "fixtures")
SIGMA_FIXTURES = os.path.join(FIXTURES, "sigma")
BROKEN_FIXTURES = os.path.join(FIXTURES, "broken")
SAMPLE_SIGMA = os.path.join(REPO_ROOT, "samples", "sigma")
INVENTORY = os.path.join(REPO_ROOT, "inventory", "ruxchipher-detections.json")
TARGETS = os.path.join(REPO_ROOT, "inventory", "lab-targets.txt")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
