Intro
=====

stinkypy is a library to aid in finding patterns associated with security 
issues within diffs. Specifically, it's intended to be used within 
pre-commit hooks, and during review to bring potential security issues to the
attention of reviewers.

stinkypy is most useful when you do reviews via GitHub PRs, and has a few tools
centered around that (like the ability to generate links to problematic lines on
GitHub,) but it should work fine with any unified diff.

Inspiration
===========

stinkypy was mostly inspired by [Rust's highfive bot](https://github.com/nick29581/highfive)
and a conversation with some nice folks from Facebook's security team.
