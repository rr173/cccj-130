#!/usr/bin/env python3
"""以隔离模式运行全部测试：python3 -I run_tests.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    root = os.path.dirname(os.path.abspath(__file__))
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(root, "tests"), pattern="test_*.py",
                            top_level_dir=root)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
