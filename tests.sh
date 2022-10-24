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

curl "https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-224.txt" > ShortMsgKAT_SHA3-224.txt
curl "https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-256.txt" > ShortMsgKAT_SHA3-256.txt
curl "https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-384.txt" > ShortMsgKAT_SHA3-384.txt
curl "https://raw.githubusercontent.com/XKCP/XKCP/master/tests/TestVectors/ShortMsgKAT_SHA3-512.txt" > ShortMsgKAT_SHA3-512.txt
popd

pushd spec
ruby generate_tests.rb
popd

rake
