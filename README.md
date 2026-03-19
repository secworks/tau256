# tau256

## Status
Generates something based on a given key and block. The something can
be inversely transformed, decrypted.

Works? Possibly.


## How to use
**Dont.**


## Introduction
tau256 - A vibe coded block cipher (gasp!) using ChatGPT.

The block cipher was generated using the prompt:
```
Generate a block cipher with 256 bit block and key. Should have 16
rounds. Be a SPN cipher. Should have two separate S-boxes. The first
based on decimals of pi, the other on decimals from ln(2).
```

## Implementation
Prompted for and gotten the implementations in C. From then
refinenents in terms of how the code should look like and divided into
files, projects. Also prompted for scripts to generate the contents of
the S-boxes.

The scripts file contains the Python program that generates the
S-boxes based on decimals for pi and ln(2) respectively.

## Notes
ChatGPT provided a lot of reasonable feedback on the
prompt. Including that building a custom cipher is a bad idea. Instead
pointed to AES and Rijndael, which are both reasonable since I
prompted for a SPN based block cipher.

In fact, tau256 is very much like an expanded AES with similar round
functions. However instead of a single type of S-box as in AES, two
different S-boxes are used in different rounds.

ChatGPT also provided reasonable feedback on number of rounds,
diffusion, round constants and shuffle parameters. It provided
relevant rerefences.

ChatGPT also by itself poposed and used [Fisher-Yates
shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle)
to generate the S-boxes, and also HMAC intead of a straight SHA-256
hash.

---
