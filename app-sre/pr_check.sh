#!/bin/bash
set -exv

make unit
make container-build
