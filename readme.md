# Torque

A minimal (standard & UNIX libraries only!) [Bittorrent](https://en.wikipedia.org/wiki/BitTorrent) client implementation in C. Download .torrent files with one terminal command.

## Motivation

This program is being developed as a side-project of mine to explore networking & memory management in C. *It is by no means production ready* and only meant as an educational tool.

It includes:
- The world's worst [Bencode](https://en.wikipedia.org/wiki/Bencode) parser.
- A low level networking api that can send & receive data from TCP sockets.
- A partial HTTP 1.0 implementation.
- A multi-threaded torrent part downloader & validator.
- A CLI argument parser.

And complies with [BEP0003](https://www.bittorrent.org/beps/bep_0003.html), [BEP0015](https://www.bittorrent.org/beps/bep_0015.html) and [BEP0023](https://www.bittorrent.org/beps/bep_0023.html)
## Resources

- I am following this [great article by Jesse Li](https://blog.jse.li/posts/torrent/) who did something similar in Go.
- Initial inspiration for this project came from a [Rust video by Jon Gjengset](https://www.youtube.com/watch?v=jf_ddGnum_4): implementing a bittorrent client using the (paid) *Build your own BitTorrent* course at [codecrafters.io](https://app.codecrafters.io/catalog)
- SHA1 implementation copied from [Steve Reid](https://gist.github.com/jrabbit/1042021)
- Concurrency code mainly from ["Operating Systems: Three Easy Pieces" by Arpaci-Dusseau](https://pages.cs.wisc.edu/~remzi/OSTEP/)

## Usage

A CLI interface is planned but not available yet.

## Building & Contributing

Only buildable on linux systems due to reliance on standard C UNIX networking apis. Build using make

```bash
$ make 
```

Please don't submit issues / merge requests while still in heavy development.
