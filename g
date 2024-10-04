#!/bin/sh
buildNum=$(grep -E '"version": "[0-9]+",' ./package.json | sed -e 's/.*"version": "\([[:digit:]]*\)".*/\1/')

git add . && git commit -m "build_$buildNum" && git push
