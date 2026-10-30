//! Zone authority check and extraction of the data-bearing labels.
//!
//! The server is authoritative for exactly one delegated zone. A query is
//! "in zone" iff its QNAME equals the zone or is a subdomain of it. Anything
//! else is REFUSED, which keeps the emulated environment realistic (a real
//! delegated authority refuses out-of-bailiwick queries).

use std::str::FromStr;

use hickory_proto::rr::Name;

pub struct Zone {
    name: Name,
}

/// The labels of a QNAME that sit *below* the zone apex, left-to-right as they
/// appear in the name (i.e. closest-to-root last). For
/// `s1.AAAA.sess01.test-telemetry.example.com` with zone
/// `test-telemetry.example.com`, this is `["s1", "AAAA", "sess01"]`.
#[derive(Debug, Clone)]
pub struct DataLabels {
    pub labels: Vec<String>,
}

impl Zone {
    pub fn new(zone_name: &str) -> Result<Self, String> {
        let name = Name::from_str(zone_name)
            .map_err(|e| format!("invalid zone name {zone_name:?}: {e}"))?
            .to_lowercase();
        Ok(Self { name })
    }

    pub fn apex(&self) -> &Name {
        &self.name
    }

    /// True if `qname` is the zone apex or a descendant of it.
    pub fn contains(&self, qname: &Name) -> bool {
        let q = qname.to_lowercase();
        self.name.zone_of(&q)
    }

    /// Extract the sub-zone labels, or `None` if the name is the apex itself or
    /// not in zone. Labels are returned in name order (leftmost first).
    pub fn data_labels(&self, qname: &Name) -> Option<DataLabels> {
        let q = qname.to_lowercase();
        if !self.name.zone_of(&q) {
            return None;
        }
        let extra = q.num_labels().checked_sub(self.name.num_labels())?;
        if extra == 0 {
            return None; // the apex itself carries no payload
        }
        let labels: Vec<String> = q
            .iter()
            .take(extra as usize)
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        Some(DataLabels { labels })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn apex_and_subdomains_are_in_zone() {
        let z = Zone::new("test-telemetry.example.com").unwrap();
        assert!(z.contains(&n("test-telemetry.example.com")));
        assert!(z.contains(&n("a.b.test-telemetry.example.com")));
    }

    #[test]
    fn out_of_zone_is_refused() {
        let z = Zone::new("test-telemetry.example.com").unwrap();
        assert!(!z.contains(&n("example.com")));
        assert!(!z.contains(&n("evil.com")));
    }

    #[test]
    fn data_labels_are_name_order() {
        let z = Zone::new("test-telemetry.example.com").unwrap();
        let d = z.data_labels(&n("s1.aaaa.sess01.test-telemetry.example.com")).unwrap();
        assert_eq!(d.labels, vec!["s1", "aaaa", "sess01"]);
    }

    #[test]
    fn apex_has_no_data_labels() {
        let z = Zone::new("test-telemetry.example.com").unwrap();
        assert!(z.data_labels(&n("test-telemetry.example.com")).is_none());
    }
}
