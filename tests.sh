#!/bin/sh

rm -fv spec/sha3_compute*.rb
rm -fv spec/sha3_digest*.rb

if [ -d "spec/data" ]
then
  rm -rfv spec/data/*
else
  mkdir "spec/data"
fi

pushd "spec/data"

if [ -f "*.txt" ]
then
  rm -v *.txt
fi

wget "https://raw.githubusercontent.com/gvanas/KeccakCodePackage/master/TestVectors/ShortMsgKAT_SHA3-224.txt"
wget "https://raw.githubusercontent.com/gvanas/KeccakCodePackage/master/TestVectors/ShortMsgKAT_SHA3-256.txt"
wget "https://raw.githubusercontent.com/gvanas/KeccakCodePackage/master/TestVectors/ShortMsgKAT_SHA3-384.txt"
wget "https://raw.githubusercontent.com/gvanas/KeccakCodePackage/master/TestVectors/ShortMsgKAT_SHA3-512.txt"

cd ".."

ruby generate_tests.rb
rake
