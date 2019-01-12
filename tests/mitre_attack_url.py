#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the artifact definitions validator."""

import glob
import os
import unittest
import yaml
import urllib.parse

from artifacts import definitions
from artifacts import errors
from artifacts import reader

from tests import test_lib

class MitreAttackURLTest(test_lib.BaseTestCase):
  """Class to test if the mitre attack url is inlcuded in artifact."""

  def testForMitreAttackURL(self):
    """Checks for Mitre Attack URL in artifacts."""
    for artifacts_file in glob.glob(os.path.join('data', 'linux.yaml')):
        with open(artifacts_file, 'rb') as yml_file:
            yml_file_load = yaml.safe_load_all(yml_file)
            my_artifacts = list(yml_file_load)
            for artifact in my_artifacts:
                if artifact.get('sources'):
                  for source in artifact.get('sources'):
                    source_type = source.get('type')
                    if not source_type == 'ARTIFACT_GROUP':
                        if artifact.get('urls'):
                            netlocs = [urllib.parse.urlparse(url).netloc for url in artifact.get('urls')]
                            self.assertIn("attack.mitre.org", netlocs, msg='add mitre url to {} in {}.'.format(artifact['name'], artifacts_file))
                        else:
                            self.assertIsNotNone(artifact.get('urls'), msg='add mitre url to {} in {}'.format(artifact['name'], artifacts_file))
                        
if __name__ == '__main__':
  unittest.main()
