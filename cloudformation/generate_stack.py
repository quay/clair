#  Copyright 2015 CoreOS, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http:# www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse
import re
import logging
import json
import yaml
import sys
import hashlib

import boto.cloudformation as cloudformation
import boto.s3 as s3

from boto.s3.key import Key
from jinja2 import FileSystemLoader, Environment, StrictUndefined
from container_cloud_config import CloudConfigContext

logger = logging.getLogger(__name__)

def userdata(value, json_indent=2):
  encoded = {
    "Fn::Base64": {
      "Fn::Join": ["", [line + '\n' for line in value.split('\n')]]
    }
  }
  return json.dumps(encoded, indent=json_indent)


def bootstrap_user_data(user_data, expiration_seconds=3600):
  uploaded = upload_s3_unique(user_data)
  signed_url = uploaded.generate_url(expires_in=expiration_seconds)

  template = ENV.get_template('bootstrap_cloudconfig.yaml')
  return template.render(cloudconfig_url=signed_url)


ENV = Environment(loader=FileSystemLoader('templates'), undefined=StrictUndefined, extensions=['jinja2.ext.do'])
ENV.filters['userdata'] = userdata
ENV.filters['bootstrap_user_data'] = bootstrap_user_data

CONFIG_CONTEXT = CloudConfigContext()
CONFIG_CONTEXT.populate_jinja_environment(ENV)

ARGUMENT = re.compile(r'(-[\w])|(--[\w]+)')

def parse_args():
  desc = 'Generate the cloud config for all nodes in the cluster.'
  parser = argparse.ArgumentParser(description=desc)
  parser.add_argument('template', help='Template file to use when creating stack')
  parser.add_argument('region', help='AWS Region',)
  parser.add_argument('cfbucket', help='AWS CloudFormation Bucket')
  parser.add_argument('accesskey', help='AWS Access Key ID')
  parser.add_argument('secretkey', help='AWS Secret Access Key')
  parser.add_argument('--json', dest='json', help='Output json config (default).',
                      action='store_true')
  parser.add_argument('--yaml', dest='json', help='Output yaml config.', action='store_false')
  parser.add_argument('--upload', dest='stackname',
                      help='Upload the stack to cloud formation with the given name.')

  parser.set_defaults(json=True)

  logger.debug('Parsing all args')
  _, unknown = parser.parse_known_args()

  logger.debug('Unknown args: %s', unknown)

  added_args = set()
  while (len(unknown) > 0 and ARGUMENT.match(unknown[0]) and
         ARGUMENT.match(unknown[0]).end() == len(unknown[0])):
    logger.debug('Adding argument: %s', unknown[0])
    added_args.add(unknown[0].lstrip('-'))
    parser.add_argument(unknown[0])
    _, unknown = parser.parse_known_args()

  logger.debug('Parsing final set of args')
  return parser.parse_args(), added_args


def upload_s3_unique(region, cfbucket, credentials, file_contents):
  logger.debug('Checking for file in s3')
  json_stack_filename = hashlib.sha1(file_contents).hexdigest()
  ess_three = s3.connect_to_region(region, **credentials)
  bucket = ess_three.get_bucket(cfbucket, validate=False)

  template_key = bucket.get_key(json_stack_filename)
  if template_key is None:
    logger.debug('Uploading file to s3')
    template_key = Key(bucket)
    template_key.key = json_stack_filename
    template_key.set_contents_from_string(file_contents)

  return template_key


def upload(region, cfbucket, credentials, stack_name, json_stack_def):
  template_key = upload_s3_unique(region, cfbucket, credentials, json_stack_def)
  template_url = template_key.generate_url(expires_in=0, query_auth=False)
  logger.debug('Template available in s3 at url: %s', template_url)

  logger.debug('Uploading stack definition with name: %s', stack_name)
  cf = cloudformation.connect_to_region(region, **credentials)
  cf.create_stack(stack_name, capabilities=['CAPABILITY_IAM'], template_url=template_url)
  logger.debug('Done uploading stack definition')


def main():
  logging.basicConfig(level=logging.DEBUG)

  all_args, added_args = parse_args()

  template_kwargs = {added: getattr(all_args, added, None) for added in added_args}
  credentials = {
    'aws_access_key_id': all_args.accesskey,
    'aws_secret_access_key': all_args.secretkey,
  }

  logger.debug('Rendering yaml template')
  template = ENV.get_template(all_args.template)
  yaml_stack_def = template.render(**template_kwargs)

  logger.debug('Validating yaml')
  parsed = yaml.load(yaml_stack_def)

  if not all_args.json and all_args.stackname:
    logger.error('YAML cannot be uploaded directly to cloud formation, please use json')
    sys.exit(1)

  if all_args.json:
    logger.debug('Rendering json')

    if all_args.stackname:
      json_stack_def = json.dumps(parsed)
      CONFIG_CONTEXT.prime_flattened_image_cache()
      upload(all_args.region, all_args.cfbucket, credentials, all_args.stackname, json_stack_def)
    else:
      print json.dumps(parsed, indent=2)
  else:
    print yaml_stack_def


if __name__ == '__main__':
  main()
