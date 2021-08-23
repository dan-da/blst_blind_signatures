# blst_blind_signatures

This is a super-rough proof of concept for performing BLS blind signatures with blst, in rust, using blst's rust bindings.

The code is in src/main.rs.   It is a single function with comments that break it into distinct client and server (mint) operations.

It was ported to rust from [this python blind signature example](https://github.com/supranational/blst/blob/9f92e2ec82291c79dab089253cc0a8d094ab76a7/bindings/python/run.me#L191) that was kindly provided by one of the blst authors.

I found it necessary to use a ton of unsafe calls into C code.  Each line of python code typically became 10+ lines of rust code.  Although based on the
same underlying C API, the python ergonomics are far superior.  There are likely better ways to do most, if not all of this.

nevertheless, it works.

Getthing this code working was very tedious.  I ended up going line by line through the python code and printing out results of each operation to ensure that the rust version behaves the same.  The modified python code is in [python/blind_sigs.py](./python/blind_sigs.py),  It should be run from within the blst repo.
