This repository contains more tests for various vlib modules
(in particular the `crypto` modules).

These tests are more extensive, but also a lot bigger and a lot slower,
than the ones in vlib/ . 

The motivation for placing them here, in a separate repo, was explained
in this discussion: <https://github.com/vlang/v/pull/22187> .

The CI of the main V repo, will use this separate repository, by running the
following task on each commit and PR:
```sh
git clone https://github.com/vlang/slower_tests
v test slower_tests
```

The same will happen with this repository's own CI, for each PR and commit.

In other words, all tests here will be run, no matter in what folder
they are placed. There is no need to mirror the folder structure of vlib/,
when you add more tests, but you can do it, if you want to.
