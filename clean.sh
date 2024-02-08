find . -name ".DS_Store" -print0 | xargs -0 rm -rf;
find . -name "*.pyc" -print0 | xargs -0 rm -rf;
rm -rf __pycache__
rm -rf .idea
