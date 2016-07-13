#!/bin/bash

mkdir -p doc
cd raml
raml2html -i api.raml -o ../doc/api.html
