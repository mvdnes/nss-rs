#!/bin/bash

if  [ "$TRAVIS_BRANCH" = "master" ] &&
    [ "$TRAVIS_PULL_REQUEST" = "false" ]
then
    echo "Publishing documentation..."

    cd $HOME
    git clone --quiet --branch=gh-pages https://${GH_TOKEN}@github.com/mvdnes/nss-rs gh-pages > /dev/null

    cd gh-pages
    git config user.email "travis@travis-ci.org"
    git config user.name "travis-ci"

    git rm -rf . > /dev/null
    cp -Rf $HOME/target/doc/* .

    git reset HEAD -- index.html > /dev/null
    git checkout -- index.html > /dev/null

    git add -f .
    git commit -m "Auto doc upload from travis"
    git push -fq origin gh-pages > /dev/null

    echo "Published documentation"
fi
