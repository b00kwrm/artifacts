#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the artifact definitions validator."""

import glob
import os
import unittest

from artifacts import definitions
from artifacts import errors
from artifacts import reader

from tests import test_lib

import yaml

class MitreAttackURLTest(test_lib.BaseTestCase):
  """Class to test if the mitre attack url is inlcuded in artifact."""

  def testForMitreAttackURL(self):
    """Checks for Mitre Attack URL in artifacts."""
    for artifacts_file in glob.glob(os.path.join('data', '*.yaml')):
        with open(artifacts_file, 'rb') as yml_file:
            yml_file_load = yaml.safe_load_all(yml_file)
            my_artifacts = list(yml_file_load)
            for artifact in my_artifacts:
                if artifact.get('urls'):
                    for url in artifact.get('urls'):
                        self.assertIn("attack.mitre.org", url, msg='add mitre url to {} in {}.'.format(artifact['name'], artifacts_file))
                        
if __name__ == '__main__':
  unittest.main()
