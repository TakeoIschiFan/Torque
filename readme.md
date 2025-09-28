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

I have tried to keep the source code as clean and minimal as possible so it should be quite readable for anyone who wants to take a look at the code. I am also planning on making a blog post write-up once the project is finished.

Development status
- [x] Bencode parser
    - [x] Parsing of bencode strings, ints
    - [x] Parsing of bencode dicts, lists, simple bencode files
    - [x] Parsing of .torrent files
- [x] TCP client
	- [x] Implement connect, close, send receive functions
	- [x] Able to ping-pong a echo server
- [x] HTTP client
	- [x] DNS lookup to get server IPs from hostnames
	- [x] HTTP GET
		Able to get HTTP 200 HTML data from [example.com](example.com)
		Query parameters unsupported for now
- [x] Core torrent stuff
	- [x] Parse a torrent file and extract the info hashes
	- [x] Connect to a tracker, retrieve list of peers
	- [ ] Downloading from peers
		- [ ] Complete Bittorrent handshake
		- [ ] Parse downloadable data from peer using bitfields
		- [ ] Pipelining
		- [ ] Assemble file and validate using the hash
- [ ] Cleanup
	- [ ] CLI interface with help command
	- [ ] Unit tests & better error handling
	- [ ] Improve readme

## Resources

- I am following this [great article by Jesse Li](https://blog.jse.li/posts/torrent/) who did something similar in Go.
- Initial inspiration for this project came from a Rust video by [Jon Gjengset](https://www.youtube.com/watch?v=jf_ddGnum_4): implementing a bittorrent client using the (paid) *Build your own BitTorrent* course at [codecrafters.io](https://app.codecrafters.io/catalog)
- SHA1 implementation copied from [Steve Reid](https://gist.github.com/jrabbit/1042021)

## Usage

A CLI interface is planned but not available yet.

## Building & Contributing

Only buildable on linux systems due to reliance on standard C UNIX networking apis. Build using make

```bash
$ make 
```

Please don't submit issues / merge requests while still in heavy development.
