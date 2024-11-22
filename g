#!/bin/sh
buildNum=$(grep -E '"version": "[0-9]+",' ./package.json | sed -e 's/.*"version": "\([[:digit:]]*\)".*/\1/')

git add . && git commit -m "1.0.$buildNum" && git push
