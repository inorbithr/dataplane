//! Redis (RESP): the command name of the first command on a connection, from an array
//! (`*2\r\n$3\r\nGET\r\n...`) or an inline command (`PING\r\n`). Keys and values are never
//! read.

use super::Detect;

/// Recognises a RESP command and returns its name, upper-cased.
pub(crate) fn command(buf: &[u8]) -> Detect<String> {
    match buf.first() {
        None => Detect::NeedMore,
        Some(b'*') => array(buf),
        Some(_) => inline(buf),
    }
}

fn array(buf: &[u8]) -> Detect<String> {
    let Some(eol) = find_crlf(buf) else {
        return if buf.len() < 16 {
            Detect::NeedMore
        } else {
            Detect::No
        };
    };
    let count = buf.get(1..eol).unwrap_or_default();
    if count.is_empty() || count.len() > 6 || !count.iter().all(u8::is_ascii_digit) {
        return Detect::No;
    }
    let rest = buf.get(eol + 2..).unwrap_or_default();
    if rest.first().is_some_and(|b| *b != b'$') {
        return Detect::No;
    }
    let Some(eol2) = find_crlf(rest) else {
        return if rest.len() < 16 {
            Detect::NeedMore
        } else {
            Detect::No
        };
    };
    let len: usize = match std::str::from_utf8(rest.get(1..eol2).unwrap_or_default())
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(n) if (1..=32).contains(&n) => n,
        _ => return Detect::No,
    };
    let Some(name) = rest.get(eol2 + 2..eol2 + 2 + len) else {
        return Detect::NeedMore;
    };
    name_of(name)
}

fn inline(buf: &[u8]) -> Detect<String> {
    let end = buf
        .iter()
        .position(|b| *b == b' ' || *b == b'\r')
        .unwrap_or(buf.len());
    if end == buf.len() {
        return if buf.len() < 16 && buf.iter().all(u8::is_ascii_alphabetic) {
            Detect::NeedMore
        } else {
            Detect::No
        };
    }
    // Inline commands are rare outside `redis-cli` and health checks: only the common
    // ones count, so plain text protocols are not mistaken for Redis.
    let name = buf.get(..end).unwrap_or_default().to_ascii_uppercase();
    if ["PING", "INFO", "QUIT", "AUTH", "HELLO"].contains(&std::str::from_utf8(&name).unwrap_or(""))
    {
        name_of(&name)
    } else {
        Detect::No
    }
}

fn name_of(name: &[u8]) -> Detect<String> {
    if name
        .iter()
        .all(|b| b.is_ascii_alphabetic() || *b == b'.' || *b == b'_')
    {
        Detect::Yes(String::from_utf8_lossy(name).to_ascii_uppercase())
    } else {
        Detect::No
    }
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        let set = b"*3\r\n$3\r\nset\r\n$4\r\nuser\r\n$6\r\nsecret\r\n";
        assert_eq!(command(set), Detect::Yes("SET".into()));
        assert_eq!(command(b"PING\r\n"), Detect::Yes("PING".into()));
        for n in 0..set.len() {
            assert_ne!(command(&set[..n]), Detect::No, "{n}");
        }
        assert_eq!(command(b"GET / HTTP/1.1\r\n"), Detect::No);
        assert_eq!(command(b"*1\r\n:5\r\n"), Detect::No);
    }
}
