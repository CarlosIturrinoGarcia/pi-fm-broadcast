#!/bin/bash
# Script to remove broadcast.env from git history
# WARNING: This rewrites git history and requires force push

set -e

echo "⚠️  WARNING: This script will rewrite git history!"
echo "⚠️  All collaborators will need to re-clone the repository!"
echo ""
echo "This will:"
echo "1. Remove broadcast.env from all commits"
echo "2. Garbage collect the old objects"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Step 1: Removing broadcast.env from git history..."
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch broadcast.env' \
  --prune-empty --tag-name-filter cat -- --all

echo ""
echo "Step 2: Cleaning up references..."
rm -rf .git/refs/original/

echo ""
echo "Step 3: Garbage collecting..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo ""
echo "✅ broadcast.env has been removed from git history!"
echo ""
echo "Next steps:"
echo "1. Verify the file is gone: git log --all --full-history -- broadcast.env"
echo "2. Force push to remote: git push --force --all"
echo "3. Rotate your AWS credentials immediately!"
echo ""
echo "⚠️  Note: Anyone who has cloned this repo needs to re-clone it!"
