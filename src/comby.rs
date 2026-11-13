//! A mutator that replaces the input with a program from a
//! [comby-decomposer](https://github.com/comby-tools/comby-decomposer) server.
//!
//! This is the comby mode of afl-compiler-fuzzer. The server is given
//! templates and fragments decomposed from a corpus of valid programs, and
//! answers each `POST /mutate` with a new program built from them (in
//! `--generate 1.0` mode it ignores the posted input and generates from
//! scratch). Start the server as described in the comby-decomposer README; for
//! large corpora, give Node a larger stack (`ulimit -s unlimited` and
//! `node --stack-size=60000 server.js ...`), or many requests fail.
//!
//! Because each successful request replaces the whole input, the mutator makes
//! at most one request per execution: later calls before the next
//! [`Mutator::post_exec`] are skipped. Requests are much slower than byte-level
//! mutations, so give this mutator a small share of the stacked steps.
//!
//! Any failure (server down, timeout, a non-200 status, an empty or oversized
//! body) makes the mutation [`MutationResult::Skipped`], so the fuzzer goes on
//! without the server. The first failure is logged as a warning.

use alloc::{borrow::Cow, format, vec::Vec};
use core::time::Duration;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
};

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::{HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::HasMaxSize,
};
use libafl_bolts::Named;

/// Inputs shorter than this are not sent.
const MIN_REQUEST_LEN: usize = 5;

/// Room for the response's status line and headers.
const MAX_HEADER_LEN: usize = 65536;

/// Default port of comby-decomposer's server.
pub const DEFAULT_COMBY_PORT: u16 = 4448;

/// Asks a comby-decomposer server for a new program, and replaces the input
/// with it. See the [module documentation](self).
#[derive(Debug)]
pub struct CombyMutator {
    addrs: Vec<SocketAddr>,
    timeout: Duration,
    requests: u64,
    failures: u64,
    warned: bool,
    /// Whether a request was made since the last execution.
    requested: bool,
}

impl CombyMutator {
    /// Creates a mutator for the server at `host:port`, with a 2 second
    /// timeout. Fails only if `host` cannot be resolved; the server need not be
    /// up yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IllegalArgument`] if `host` does not resolve.
    pub fn new(host: &str, port: u16) -> Result<Self, Error> {
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|e| Error::illegal_argument(format!("cannot resolve {host}: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(Error::illegal_argument(format!("no address for {host}")));
        }
        Ok(Self {
            addrs,
            timeout: Duration::from_secs(2),
            requests: 0,
            failures: 0,
            warned: false,
            requested: false,
        })
    }

    /// Sets the connect, read, and write timeout for each request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Requests made so far, and how many of them failed or returned nothing.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.requests, self.failures)
    }

    fn connect(&self) -> std::io::Result<TcpStream> {
        let mut last = None;
        for addr in &self.addrs {
            match TcpStream::connect_timeout(addr, self.timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(self.timeout))?;
                    stream.set_write_timeout(Some(self.timeout))?;
                    stream.set_nodelay(true)?;
                    return Ok(stream);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no address")))
    }

    /// POSTs `body` to `/mutate` and returns the response body, if it is a 200
    /// with a body of 1 to `max_body` bytes.
    fn request(&self, body: &[u8], max_body: usize) -> Result<Option<Vec<u8>>, std::io::Error> {
        let mut stream = self.connect()?;
        let head = format!(
            "POST /mutate HTTP/1.0\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;

        let cap = (max_body + MAX_HEADER_LEN) as u64;
        let mut resp = Vec::new();
        // Read one byte past the cap, to tell a full response from a cut one.
        stream.take(cap + 1).read_to_end(&mut resp)?;
        if resp.len() as u64 > cap {
            return Ok(None);
        }

        if resp.len() < 12 || !resp.starts_with(b"HTTP/1.") || &resp[8..12] != b" 200" {
            return Ok(None);
        }
        let Some(end) = resp.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Ok(None);
        };
        let body = &resp[end + 4..];
        // An empty body means the server had nothing to offer.
        if body.is_empty() || body.len() > max_body {
            return Ok(None);
        }
        Ok(Some(body.to_vec()))
    }

    fn fail(&mut self, why: &dyn core::fmt::Display) {
        self.failures += 1;
        if !self.warned {
            self.warned = true;
            log::warn!(
                "comby server {:?}: {why}; failed requests are skipped",
                self.addrs[0]
            );
        }
    }
}

impl<I, S> Mutator<I, S> for CombyMutator
where
    S: HasMaxSize,
    I: ResizableMutator<u8> + HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let bytes = input.mutator_bytes();
        // The server handles ASCII text only.
        if self.requested || bytes.len() < MIN_REQUEST_LEN || !bytes.is_ascii() {
            return Ok(MutationResult::Skipped);
        }

        self.requested = true;
        self.requests += 1;
        match self.request(bytes, state.max_size()) {
            Ok(Some(program)) => {
                let len = input.mutator_bytes().len();
                input.splice(0..len, program);
                Ok(MutationResult::Mutated)
            }
            Ok(None) => {
                self.fail(&"bad or empty response");
                Ok(MutationResult::Skipped)
            }
            Err(e) => {
                self.fail(&e);
                Ok(MutationResult::Skipped)
            }
        }
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.requested = false;
        Ok(())
    }
}

impl Named for CombyMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CombyMutator");
        &NAME
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};
    use core::time::Duration;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use libafl::{
        inputs::{BytesInput, HasMutatorBytes},
        mutators::{MutationResult, Mutator},
        state::NopState,
    };

    use super::CombyMutator;

    /// Serves `count` requests, answering each with `reply(request_body)`, and
    /// returns the port.
    fn serve(count: usize, reply: fn(&[u8]) -> Vec<u8>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().take(count) {
                let mut stream = stream.unwrap();
                let mut req = Vec::new();
                let mut buf = [0; 4096];
                // Read until the declared body has arrived.
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    req.extend_from_slice(&buf[..n]);
                    if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&req[..end]).to_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if req.len() >= end + 4 + len {
                            let resp = reply(&req[end + 4..end + 4 + len]);
                            stream.write_all(&resp).unwrap();
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
            }
        });
        port
    }

    fn ok(body: &[u8]) -> Vec<u8> {
        [
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            body,
        ]
        .concat()
    }

    fn mutate(port: u16, data: &[u8]) -> (MutationResult, Vec<u8>, (u64, u64)) {
        let mut state = NopState::<BytesInput>::new();
        let mut mutator = CombyMutator::new("127.0.0.1", port)
            .unwrap()
            .with_timeout(Duration::from_secs(5));
        let mut input = BytesInput::new(data.to_vec());
        let result = mutator.mutate(&mut state, &mut input).unwrap();
        (result, input.mutator_bytes().to_vec(), mutator.stats())
    }

    #[test]
    fn test_replaces_input() {
        let port = serve(1, |req| ok(&[b"-- from comby\n", req].concat()));
        let (result, out, stats) = mutate(port, b"print(1)\n");
        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(out, b"-- from comby\nprint(1)\n");
        assert_eq!(stats, (1, 0));
    }

    #[test]
    fn test_error_status_skips() {
        let port = serve(1, |_| {
            b"HTTP/1.1 500 Internal Server Error\r\n\r\noops".to_vec()
        });
        let (result, out, stats) = mutate(port, b"print(1)\n");
        assert_eq!(result, MutationResult::Skipped);
        assert_eq!(out, b"print(1)\n");
        assert_eq!(stats, (1, 1));
    }

    #[test]
    fn test_empty_body_skips() {
        let port = serve(1, |_| ok(b""));
        assert_eq!(mutate(port, b"print(1)\n").0, MutationResult::Skipped);
    }

    #[test]
    fn test_oversized_body_skips() {
        // NopState's max size is 16 KiB.
        let port = serve(1, |_| ok(&[b'x'; 20_000]));
        assert_eq!(mutate(port, b"print(1)\n").0, MutationResult::Skipped);
    }

    #[test]
    fn test_no_server_skips() {
        // Bind and drop a listener, so the port is (almost certainly) closed.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (result, _, stats) = mutate(port, b"print(1)\n");
        assert_eq!(result, MutationResult::Skipped);
        assert_eq!(stats, (1, 1));
    }

    #[test]
    fn test_one_request_per_execution() {
        let port = serve(2, |req| ok(&[b"--\n", req].concat()));
        let mut state = NopState::<BytesInput>::new();
        let mut mutator = CombyMutator::new("127.0.0.1", port).unwrap();
        let mut input = BytesInput::new(b"print(1)\n".to_vec());
        let mut step = |m: &mut CombyMutator, i: &mut BytesInput| m.mutate(&mut state, i).unwrap();

        assert_eq!(step(&mut mutator, &mut input), MutationResult::Mutated);
        assert_eq!(step(&mut mutator, &mut input), MutationResult::Skipped);
        assert_eq!(mutator.stats(), (1, 0));

        Mutator::<BytesInput, _>::post_exec(&mut mutator, &mut NopState::<BytesInput>::new(), None)
            .unwrap();
        assert_eq!(step(&mut mutator, &mut input), MutationResult::Mutated);
        assert_eq!(input.mutator_bytes(), b"--\n--\nprint(1)\n");
        assert_eq!(mutator.stats(), (2, 0));
    }

    #[test]
    fn test_not_sent() {
        // Too short, or not ASCII: no request at all.
        assert_eq!(mutate(1, b"x=1").2, (0, 0));
        assert_eq!(mutate(1, "print('é')".as_bytes()).2, (0, 0));
    }
}
