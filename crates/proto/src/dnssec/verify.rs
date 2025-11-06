// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! FIXME(NET)

use core::{clone::Clone, fmt::Display};
use std::collections::HashMap;

use tracing::{debug, trace, warn};

use crate::{
    dnssec::{
        Proof, ProofError, ProofErrorKind, Verifier,
        rdata::{DNSKEY, DS, NSEC, RRSIG},
    },
    error::ProtoError,
    op::{DnsResponse, Query, ResponseCode},
    rr::{Name, Record, RecordType, RecordTypeSet, SerialNumber, resource::RecordRef},
};

pub use self::rrset::Rrset;

/// FIXME(NET)
pub fn verify_rrsig_with_keys(
    dnskey_message: DnsResponse,
    rrsig: &RecordRef<'_, RRSIG>,
    rrset: &Rrset<'_>,
    current_time: u32,
) -> Option<(Proof, Option<u32>)> {
    let mut tag_count = HashMap::<u16, usize>::new();

    if (rrset.record_type == RecordType::NSEC || rrset.record_type == RecordType::NSEC3)
        && rrset.name.num_labels() != rrsig.data().input().num_labels
    {
        warn!(
            "{} record signature claims to be expanded from a wildcard",
            rrset.record_type
        );
        return None;
    }

    // DNSKEYs were already validated by the inner query in the above lookup
    let dnskeys = dnskey_message.answers().iter().filter_map(|r| {
        let dnskey = r.try_borrow::<DNSKEY>()?;

        let tag = match dnskey.data().calculate_key_tag() {
            Ok(tag) => tag,
            Err(e) => {
                warn!("unable to calculate key tag: {e:?}; skipping key");
                return None;
            }
        };

        match tag_count.get_mut(&tag) {
            Some(n_keys) => {
                *n_keys += 1;
                if *n_keys > MAX_KEY_TAG_COLLISIONS {
                    warn!("too many ({n_keys}) DNSKEYs with key tag {tag}; skipping");
                    return None;
                }
            }
            None => _ = tag_count.insert(tag, 1),
        }

        Some(dnskey)
    });

    let mut all_insecure = None;
    for dnskey in dnskeys {
        match dnskey.proof() {
            Proof::Secure => {
                all_insecure = Some(false);
                if let Ok(proof) =
                    verify_rrset_with_dnskey(dnskey, dnskey.proof(), rrsig, rrset, current_time)
                {
                    return Some((proof.0, proof.1));
                }
            }
            Proof::Insecure => {
                all_insecure.get_or_insert(true);
            }
            _ => all_insecure = Some(false),
        }
    }

    if all_insecure.unwrap_or(false) {
        // inherit Insecure state
        Some((Proof::Insecure, None))
    } else {
        None
    }
}

/// Find the SOA record in the response and return its name.
pub fn find_soa_name(verified_message: &DnsResponse) -> Result<&Name, ProtoError> {
    for record in verified_message.authorities() {
        if record.record_type() == RecordType::SOA {
            return Ok(record.name());
        }
    }

    Err(ProtoError::from(
        "could not validate negative response missing SOA",
    ))
}

/// This verifies a DNSKEY record against DS records from a secure delegation.
pub fn verify_dnskey(
    rr: &RecordRef<'_, DNSKEY>,
    ds_records: &[Record<DS>],
) -> Result<Proof, ProofError> {
    let key_rdata = rr.data();
    let key_tag = key_rdata.calculate_key_tag().map_err(|_| {
        ProofError::new(
            Proof::Insecure,
            ProofErrorKind::ErrorComputingKeyTag {
                name: rr.name().clone(),
            },
        )
    })?;
    let key_algorithm = key_rdata.algorithm();

    if !key_algorithm.is_supported() {
        return Err(ProofError::new(
            Proof::Insecure,
            ProofErrorKind::UnsupportedKeyAlgorithm,
        ));
    }

    // DS check if covered by DS keys
    let mut key_authentication_attempts = 0;
    for r in ds_records.iter().filter(|ds| ds.proof().is_secure()) {
        if r.data().algorithm() != key_algorithm {
            trace!(
                "skipping DS record due to algorithm mismatch, expected algorithm {}: ({}, {})",
                key_algorithm,
                r.name(),
                r.data(),
            );

            continue;
        }

        if r.data().key_tag() != key_tag {
            trace!(
                "skipping DS record due to key tag mismatch, expected tag {key_tag}: ({}, {})",
                r.name(),
                r.data(),
            );

            continue;
        }

        // Count the number of DS records with the same algorithm and key tag as this DNSKEY.
        // Ignore remaining DS records if there are too many key tag collisions. Doing so before
        // checking hashes or signatures protects us from KeyTrap denial of service attacks.
        key_authentication_attempts += 1;
        if key_authentication_attempts > MAX_KEY_TAG_COLLISIONS {
            warn!(
                key_tag,
                attempts = key_authentication_attempts,
                "too many DS records with same key tag; skipping"
            );
            continue;
        }

        if !r.data().covers(rr.name(), key_rdata).unwrap_or(false) {
            continue;
        }

        debug!(
            "validated dnskey ({}, {key_rdata}) with {} {}",
            rr.name(),
            r.name(),
            r.data(),
        );

        // If this key is valid, then it is secure
        return Ok(Proof::Secure);
    }

    trace!("bogus dnskey: {}", rr.name());
    Err(ProofError::new(
        Proof::Bogus,
        ProofErrorKind::DnsKeyHasNoDs {
            name: rr.name().clone(),
        },
    ))
}

/// Verifies the given SIG of the RRSET with the DNSKEY.
pub fn verify_rrset_with_dnskey(
    dnskey: RecordRef<'_, DNSKEY>,
    dnskey_proof: Proof,
    rrsig: &RecordRef<'_, RRSIG>,
    rrset: &Rrset<'_>,
    current_time: u32,
) -> Result<(Proof, Option<u32>), ProofError> {
    match dnskey_proof {
        Proof::Secure => (),
        proof => {
            debug!("insecure dnskey {} {}", dnskey.name(), dnskey.data());
            return Err(ProofError::new(
                proof,
                ProofErrorKind::InsecureDnsKey {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().input.key_tag,
                },
            ));
        }
    }

    if dnskey.data().revoke() {
        debug!("revoked dnskey {} {}", dnskey.name(), dnskey.data());
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::DnsKeyRevoked {
                name: dnskey.name().clone(),
                key_tag: rrsig.data().input.key_tag,
            },
        ));
    } // TODO: does this need to be validated? RFC 5011
    if !dnskey.data().zone_key() {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::NotZoneDnsKey {
                name: dnskey.name().clone(),
                key_tag: rrsig.data().input.key_tag,
            },
        ));
    }
    if dnskey.data().algorithm() != rrsig.data().input.algorithm {
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::AlgorithmMismatch {
                rrsig: rrsig.data().input.algorithm,
                dnskey: dnskey.data().algorithm(),
            },
        ));
    }

    let validity = RrsigValidity::check(*rrsig, rrset, dnskey, current_time);
    if !matches!(validity, RrsigValidity::ValidRrsig) {
        // TODO better error handling when the error payload is not immediately discarded by
        // the caller
        return Err(ProofError::new(
            Proof::Bogus,
            ProofErrorKind::Msg(format!("{validity:?}")),
        ));
    }

    dnskey
        .data()
        .verify_rrsig(
            &rrset.name,
            rrset.record_class,
            rrsig.data(),
            rrset.records.iter().copied(),
        )
        .map(|_| {
            debug!(
                "validated ({}, {:?}) with ({}, {})",
                rrset.name,
                rrset.record_type,
                dnskey.name(),
                dnskey.data()
            );
            (
                Proof::Secure,
                Some(rrsig.data().authenticated_ttl(rrset.record(), current_time)),
            )
        })
        .map_err(|e| {
            debug!(
                "failed validation of ({}, {:?}) with ({}, {})",
                rrset.name,
                rrset.record_type,
                dnskey.name(),
                dnskey.data()
            );
            ProofError::new(
                Proof::Bogus,
                ProofErrorKind::DnsKeyVerifyRrsig {
                    name: dnskey.name().clone(),
                    key_tag: rrsig.data().input.key_tag,
                    error: e,
                },
            )
        })
}

#[derive(Clone, Copy, Debug)]
enum RrsigValidity {
    /// RRSIG has already expired
    ExpiredRrsig,
    /// RRSIG is valid
    ValidRrsig,
    /// DNSKEY does not match RRSIG
    WrongDnskey,
    /// RRSIG does not match RRset
    WrongRrsig,
}

impl RrsigValidity {
    // see section 5.3.1 of RFC4035 "Checking the RRSIG RR Validity"
    fn check(
        rrsig: RecordRef<'_, RRSIG>,
        rrset: &Rrset<'_>,
        dnskey: RecordRef<'_, DNSKEY>,
        current_time: u32,
    ) -> Self {
        let Ok(dnskey_key_tag) = dnskey.data().calculate_key_tag() else {
            return Self::WrongDnskey;
        };

        let current_time = SerialNumber(current_time);
        let sig_input = rrsig.data().input();
        if !(
            // "The RRSIG RR and the RRset MUST have the same owner name and the same class"
            rrsig.name() == &rrset.name &&
            rrsig.dns_class() == rrset.record_class &&

            // "The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset"
            // TODO(^) the zone name is in the SOA record, which is not accessible from here

            // "The RRSIG RR's Type Covered field MUST equal the RRset's type"
            sig_input.type_covered == rrset.record_type &&

            // "The number of labels in the RRset owner name MUST be greater than or equal to the value
            // in the RRSIG RR's Labels field"
            rrset.name.num_labels() >= sig_input.num_labels
        ) {
            return Self::WrongRrsig;
        }

        // Section 3.1.5 of RFC4034 states that 'all comparisons involving these fields MUST use
        // "Serial number arithmetic", as defined in RFC1982'
        if !(
            // "The validator's notion of the current time MUST be less than or equal to the time listed
            // in the RRSIG RR's Expiration field"
            current_time <= sig_input.sig_expiration &&

            // "The validator's notion of the current time MUST be greater than or equal to the time
            // listed in the RRSIG RR's Inception field"
            current_time >= sig_input.sig_inception
        ) {
            return Self::ExpiredRrsig;
        }

        if !(
            // "The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name,
            // algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset"
            &sig_input.signer_name == dnskey.name() &&
            sig_input.algorithm == dnskey.data().algorithm() &&
            sig_input.key_tag == dnskey_key_tag &&
            // "The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the
            // Zone Flag bit (DNSKEY RDATA Flag bit 7) set"
            dnskey.data().zone_key()
        ) {
            return Self::WrongDnskey;
        }

        Self::ValidRrsig
    }
}

/// Verifies NSEC records
///
/// ```text
/// RFC 4035             DNSSEC Protocol Modifications            March 2005
///
/// 5.4.  Authenticated Denial of Existence
///
///  A resolver can use authenticated NSEC RRs to prove that an RRset is
///  not present in a signed zone.  Security-aware name servers should
///  automatically include any necessary NSEC RRs for signed zones in
///  their responses to security-aware resolvers.
///
///  Denial of existence is determined by the following rules:
///
///  o  If the requested RR name matches the owner name of an
///     authenticated NSEC RR, then the NSEC RR's type bit map field lists
///     all RR types present at that owner name, and a resolver can prove
///     that the requested RR type does not exist by checking for the RR
///     type in the bit map.  If the number of labels in an authenticated
///     NSEC RR's owner name equals the Labels field of the covering RRSIG
///     RR, then the existence of the NSEC RR proves that wildcard
///     expansion could not have been used to match the request.
///
///  o  If the requested RR name would appear after an authenticated NSEC
///     RR's owner name and before the name listed in that NSEC RR's Next
///     Domain Name field according to the canonical DNS name order
///     defined in [RFC4034], then no RRsets with the requested name exist
///     in the zone.  However, it is possible that a wildcard could be
///     used to match the requested RR owner name and type, so proving
///     that the requested RRset does not exist also requires proving that
///     no possible wildcard RRset exists that could have been used to
///     generate a positive response.
///
///  In addition, security-aware resolvers MUST authenticate the NSEC
///  RRsets that comprise the non-existence proof as described in Section
///  5.3.
///
///  To prove the non-existence of an RRset, the resolver must be able to
///  verify both that the queried RRset does not exist and that no
///  relevant wildcard RRset exists.  Proving this may require more than
///  one NSEC RRset from the zone.  If the complete set of necessary NSEC
///  RRsets is not present in a response (perhaps due to message
///  truncation), then a security-aware resolver MUST resend the query in
///  order to attempt to obtain the full collection of NSEC RRs necessary
///  to verify the non-existence of the requested RRset.  As with all DNS
///  operations, however, the resolver MUST bound the work it puts into
///  answering any particular query.
///
///  Since a validated NSEC RR proves the existence of both itself and its
///  corresponding RRSIG RR, a validator MUST ignore the settings of the
///  NSEC and RRSIG bits in an NSEC RR.
/// ```
pub fn verify_nsec(
    query: &Query,
    soa_name: &Name,
    response_code: ResponseCode,
    nsecs: &[(&Name, &NSEC)],
) -> Proof {
    // TODO: consider converting this to Result, and giving explicit reason for the failure

    if response_code != ResponseCode::NXDomain && response_code != ResponseCode::NoError {
        return nsec1_yield(Proof::Bogus, query, "unsupported response code");
    }

    let handle_matching_nsec = |type_set: &RecordTypeSet,
                                message_secure: &str,
                                message_record_exists: &str,
                                message_name_exists| {
        if type_set.contains(query.query_type()) || type_set.contains(RecordType::CNAME) {
            nsec1_yield(Proof::Bogus, query, message_record_exists)
        } else if response_code == ResponseCode::NoError {
            nsec1_yield(Proof::Secure, query, message_secure)
        } else {
            nsec1_yield(Proof::Bogus, query, message_name_exists)
        }
    };

    // Look for an NSEC record that matches the query name first. If such a record exists, then the
    // query type and CNAME must mot be present at this name.
    if let Some((_, nsec_data)) = nsecs.iter().find(|(name, _)| query.name() == *name) {
        return handle_matching_nsec(
            nsec_data.type_set(),
            "direct match",
            "direct match, record should be present",
            "nxdomain when direct match exists",
        );
    }

    if !soa_name.zone_of(query.name()) {
        return nsec1_yield(Proof::Bogus, query, "SOA record is for the wrong zone");
    }

    let Some((covering_nsec_name, covering_nsec_data)) =
        find_nsec_covering_record(soa_name, query.name(), nsecs)
    else {
        return nsec1_yield(
            Proof::Bogus,
            query,
            "no NSEC record matches or covers the query name",
        );
    };

    // Identify the names that exist (including names of empty non terminals) that are parents of
    // the query name. Pick the longest such name, because wildcard synthesis would start looking
    // for a wildcard record there.
    let mut next_closest_encloser = soa_name.clone();
    for seed_name in [covering_nsec_name, covering_nsec_data.next_domain_name()] {
        if !soa_name.zone_of(seed_name) {
            // This is a sanity check, in case the next domain name is out-of-bailiwick.
            continue;
        }
        let mut candidate_name = seed_name.clone();
        while candidate_name.num_labels() > next_closest_encloser.num_labels() {
            if candidate_name.zone_of(query.name()) {
                next_closest_encloser = candidate_name;
                break;
            }
            candidate_name = candidate_name.base_name();
        }
    }
    let Ok(wildcard_name) = next_closest_encloser.prepend_label("*") else {
        // This fails if the prepended label is invalid or if the wildcard name would be too long.
        // However, we already know that the query name is not too long. The next closest enclosing
        // name must be strictly shorter than the query name, since we know that there is no NSEC
        // record matching the query name. Thus the query name must be as long or longer than this
        // wildcard name we are trying to construct, because we removed at least one label from the
        // query name, and tried to add a single-byte label. This error condition should thus be
        // unreachable.
        return nsec1_yield(
            Proof::Bogus,
            query,
            "unreachable error constructing wildcard name",
        );
    };
    debug!(%wildcard_name, "looking for NSEC for wildcard");

    if let Some((_, wildcard_nsec_data)) = nsecs.iter().find(|(name, _)| &wildcard_name == *name) {
        // Wildcard NSEC exists.
        return handle_matching_nsec(
            wildcard_nsec_data.type_set(),
            "wildcard match",
            "wildcard match, record should be present",
            "nxdomain when wildcard match exists",
        );
    }

    if find_nsec_covering_record(soa_name, &wildcard_name, nsecs).is_some() {
        // Covering NSEC records exist for both the query name and the wildcard name.
        if response_code == ResponseCode::NXDomain {
            return nsec1_yield(Proof::Secure, query, "no direct match, no wildcard");
        } else {
            return nsec1_yield(Proof::Bogus, query, "expected NXDOMAIN");
        }
    }

    nsec1_yield(
        Proof::Bogus,
        query,
        "no NSEC record matches or covers the wildcard name",
    )
}

/// Find the NSEC record covering `test_name`, if any.
fn find_nsec_covering_record<'a>(
    soa_name: &Name,
    test_name: &Name,
    nsecs: &[(&'a Name, &'a NSEC)],
) -> Option<(&'a Name, &'a NSEC)> {
    nsecs.iter().copied().find(|(nsec_name, nsec_data)| {
        let next_domain_name = nsec_data.next_domain_name();
        soa_name.zone_of(nsec_name)
            && test_name > nsec_name
            && (test_name < next_domain_name || next_domain_name == soa_name)
    })
}

/// Logs a debug message and returns a [`Proof`]. This is specific to NSEC validation.
fn nsec1_yield(proof: Proof, query: &Query, msg: impl Display) -> Proof {
    proof_log_yield(proof, query, "nsec1", msg)
}

/// Logs a debug message and yields a Proof type for return
pub fn proof_log_yield(proof: Proof, query: &Query, nsec_type: &str, msg: impl Display) -> Proof {
    debug!(
        "{nsec_type} proof for {name}, returning {proof}: {msg}",
        name = query.name()
    );
    proof
}

mod rrset {
    use alloc::vec::Vec;

    use crate::rr::{DNSClass, Name, Record, RecordType};

    // TODO: combine this with crate::rr::RecordSet?
    /// FIXME(NET)
    #[derive(Debug)]
    pub struct Rrset<'r> {
        /// FIXME(NET)
        pub name: Name,
        /// FIXME(NET)
        pub record_class: DNSClass,
        /// FIXME(NET)
        pub record_type: RecordType,
        /// FIXME(NET)
        pub records: Vec<&'r Record>,
    }

    impl<'r> Rrset<'r> {
        /// FIXME(NET)
        pub fn new(record: &'r Record) -> Self {
            Self {
                name: record.name().clone(),
                record_class: record.dns_class(),
                record_type: record.record_type(),
                records: vec![record],
            }
        }

        /// Adds `record` to this RRset IFF it belongs to it
        pub fn add(&mut self, record: &'r Record) {
            if self.name == *record.name()
                && self.record_type == record.record_type()
                && self.record_class == record.dns_class()
            {
                self.records.push(record);
            }
        }

        /// Returns the first (main) record.
        pub fn record(&self) -> &Record {
            self.records[0]
        }
    }
}

/// The maximum number of key tag collisions to accept when:
///
/// 1) Retrieving DNSKEY records for a zone
/// 2) Retrieving DS records from a parent zone
///
/// Any colliding records encountered beyond this limit will be discarded.
const MAX_KEY_TAG_COLLISIONS: usize = 2;

/// The maximum number of RRSIGs to attempt to validate for each RRSET.
pub const MAX_RRSIGS_PER_RRSET: usize = 8;
