#!/bin/bash

# Exit on any error
set -e

echo "GitHub Repository Push Script"
echo "============================"
echo ""
echo "This script will help you push your SOC SOP Generator to GitHub."
echo ""
echo "Before running this script:"
echo "1. Create a new repository on GitHub"
echo "2. Copy the repository URL (HTTPS or SSH)"
echo "3. Make sure you have git configured with your credentials"
echo ""
echo "Example repository URLs:"
echo "  HTTPS: https://github.com/yourusername/soc-sop-generator.git"
echo "  SSH:   git@github.com:yourusername/soc-sop-generator.git"
echo ""

# Check if remote is already configured
if git remote -v | grep -q origin; then
    echo "Remote 'origin' is already configured:"
    git remote -v
    echo ""
    read -p "Do you want to change it? (y/n): " change_remote
    if [[ $change_remote == "y" || $change_remote == "Y" ]]; then
        git remote remove origin
    else
        echo "Using existing remote configuration."
        echo ""
        echo "Pushing to GitHub..."
        git push -u origin master --force
        exit 0
    fi
fi

# Get repository URL from user
echo "Enter your GitHub repository URL:"
read -p "Repository URL: " repo_url

if [[ -z "$repo_url" ]]; then
    echo "ERROR: No repository URL provided."
    exit 1
fi

# Add remote
echo ""
echo "Adding remote origin..."
git remote add origin "$repo_url"

# Check if remote was added successfully
if ! git remote -v | grep -q origin; then
    echo "ERROR: Failed to add remote origin."
    exit 1
fi

# Verify remote
echo ""
echo "Remote configuration:"
git remote -v

# Push to GitHub
echo ""
echo "Pushing to GitHub..."
echo "This will push your initial commit to the master branch."
echo ""

read -p "Continue? (y/n): " continue_push

if [[ $continue_push == "y" || $continue_push == "Y" ]]; then
    git push -u origin master --force
    
    if [[ $? -eq 0 ]]; then
        echo ""
        echo "SUCCESS: Repository pushed to GitHub!"
        echo ""
        echo "Your repository is now available at:"
        echo "$repo_url"
        echo ""
        echo "Next steps:"
        echo "1. Add a description to your GitHub repository"
        echo "2. Add topics/tags for better discoverability"
        echo "3. Consider adding a LICENSE file if not MIT"
        echo "4. Set up branch protection rules if needed"
    else
        echo ""
        echo "ERROR: Failed to push to GitHub."
        echo "Please check your credentials and repository URL."
    fi
else
    echo "Push cancelled."
fi 