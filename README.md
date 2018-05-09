ecrecover
=====

A Proof of Concept Erlang port application providing limited access to recoverable sign and pub_key recovery functions in libsecp256k1.
It works for me. It may not work for you. I do not provide support for included code.

Notes
-----

Signatures are in raw compact form (no DER). Recovered public key has no type signature (no header).


Build
-----

You need Linux environment, git, autotools, make, erlang runtime, rebar3 and other tools I forgot I have installed in my env.

    $ rebar3 compile
