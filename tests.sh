#!/bin/sh

rm -fv spec/sha3_compute*.rb
rm -fv spec/sha3_digest*.rb

if [ -d "spec/data" ] 
then
  rm -rfv spec/data/*
else
  mkdir "spec/data"
fi

cd "spec/data"

if [ -f "KeccakTestVectors.zip" ] 
then
  rm -v "KeccakTestVectors.zip"
fi

wget "http://cloud.github.com/downloads/johanns/sha3/KeccakTestVectors.zip"
unzip KeccakTestVectors.zip

cd ".."

ruby generate_tests.rb
rake