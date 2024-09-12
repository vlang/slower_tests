This folder contains more tests for V's `crypto` related modules.

These tests are more extensive, but also a lot bigger and a lot slower,
than the ones in vlib/crypto. 

The motivation for placing them here, in a separate repo, was explained
in this discussion: <https://github.com/vlang/v/pull/22187> .

The CI of the main V repo, will use this separate repository, by running the
following task on each commit and PR:
```sh
git clone https://github.com/vlang/hash_validation_tests
v test hash_validation_tests
```

In other words, all tests here will be run, no matter in what folder
they are placed. There is no need to mirror the folder structure of vlib/crypto,
when you add more tests, but you can do it, if you want to.
