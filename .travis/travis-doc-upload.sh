#!/bin/sh

# License: CC0 1.0 Universal
# https://creativecommons.org/publicdomain/zero/1.0/legalcode

set -e

SCRIPT_PATH=.travis

. $SCRIPT_PATH/travis-doc-upload.cfg

[ "$TRAVIS_BRANCH" = master ]

[ "$TRAVIS_PULL_REQUEST" = false ]

[ "$TRAVIS_RUST_LANGUAGE" = "$DOC_RUST_VERSION" ]

eval key=\$encrypted_${SSH_KEY_TRAVIS_ID}_key
eval iv=\$encrypted_${SSH_KEY_TRAVIS_ID}_iv

mkdir -p ~/.ssh
openssl aes-256-cbc -K $key -iv $iv -in $SCRIPT_PATH/id_rsa.enc -out ~/.ssh/id_rsa -d
chmod 600 ~/.ssh/id_rsa

git clone --branch gh-pages git@github.com:$DOCS_REPO deploy_docs

cd deploy_docs
git config user.name "doc upload bot"
git config user.email "nobody@example.com"
rm -rf $PROJECT_NAME
mv ../target/doc $PROJECT_NAME
git add -A $PROJECT_NAME
git commit -qm "doc upload for $PROJECT_NAME ($TRAVIS_REPO_SLUG)"

for i in {0..5}; do
    git push -q origin gh-pages && break # redo when push fails
    git pull -r || break # give up if rebase fails
done

echo "Doc upload completed"
