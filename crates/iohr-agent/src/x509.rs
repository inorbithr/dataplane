//! Just enough DER to read a certificate's `notAfter`, so a check can report when TLS
//! expires without a full X.509 parser in the dependency tree.

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// The `notAfter` of a DER-encoded X.509 certificate, or `None` if it cannot be read.
#[must_use]
pub fn not_after(der: &[u8]) -> Option<OffsetDateTime> {
    let (0x30, cert, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(cert)? else {
        return None;
    };
    let mut rest = tbs;
    let mut fields = Vec::with_capacity(5);
    while fields.len() < 5 {
        let (tag, content, next) = tlv(rest)?;
        if !(fields.is_empty() && tag == 0xa0) {
            fields.push((tag, content));
        }
        rest = next;
    }
    // serialNumber, signature, issuer, validity
    let (0x30, validity) = fields.get(3).copied()? else {
        return None;
    };
    let (_, _, after_before) = tlv(validity)?;
    let (tag, time, _) = tlv(after_before)?;
    parse_time(tag, time)
}

fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, r) = rest.split_at_checked(n)?;
        rest = r;
        bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
    };
    let (content, rest) = rest.split_at_checked(len)?;
    Some((tag, content, rest))
}

fn parse_time(tag: u8, raw: &[u8]) -> Option<OffsetDateTime> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 if s.len() == 14 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: std::ops::Range<usize>| rest.get(r)?.parse::<u8>().ok();
    let month = Month::try_from(num(0..2)?).ok()?;
    let date = Date::from_calendar_date(year, month, num(2..4)?).ok()?;
    let time = Time::from_hms(num(4..6)?, num(6..8)?, num(8..10)?).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // A self-signed certificate made with
    // `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj /CN=t`
    // with `-not_after 20310101000000Z`.
    const CERT_B64: &str = include_str!("../tests/fixtures/cert.b64");

    #[test]
    fn reads_not_after() {
        let der = base64::engine::general_purpose::STANDARD
            .decode(CERT_B64.trim())
            .unwrap();
        let t = not_after(&der).unwrap();
        assert_eq!(t.year(), 2031);
        assert_eq!(u8::from(t.month()), 1);
        assert_eq!(t.day(), 1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(not_after(&[]).is_none());
        assert!(not_after(&[0x30, 0x82, 0xff]).is_none());
        assert!(not_after(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_none());
    }

    #[test]
    fn parses_both_time_forms() {
        let utc = parse_time(0x17, b"491231235959Z").unwrap();
        assert_eq!(utc.year(), 2049);
        let utc = parse_time(0x17, b"500101000000Z").unwrap();
        assert_eq!(utc.year(), 1950);
        let gen_time = parse_time(0x18, b"20510615120000Z").unwrap();
        assert_eq!(gen_time.year(), 2051);
        assert!(parse_time(0x18, b"2051061512000Z").is_none());
    }
}
