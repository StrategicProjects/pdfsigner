//! RFC 5280 §6.1 certificate **policy** processing: the `valid_policy_tree`,
//! policy mapping, and the explicit-policy / policy-mapping / inhibit-anyPolicy
//! counters.
//!
//! This is a from-scratch implementation of the RFC 5280 §6.1.2–6.1.6 policy
//! algorithm. It is exercised by the crate's own scenario tests and validated
//! against the NIST PKITS suite (certificate-policy section, see
//! `tests/pkits.rs`).

use std::collections::BTreeSet;

use const_oid::db::rfc5280::ANY_POLICY;
use const_oid::ObjectIdentifier;
use der::Encode;
use x509_cert::ext::pkix::{
    CertificatePolicies, InhibitAnyPolicy, PolicyConstraints, PolicyMappings,
};
use x509_cert::Certificate;

/// User-supplied policy inputs (RFC 5280 §6.1.1).
pub(crate) struct PolicyInput {
    /// Acceptable policies. Containing `anyPolicy` means "accept any".
    pub initial_policy_set: BTreeSet<ObjectIdentifier>,
    /// Whether an explicit acceptable policy is required from the start.
    pub initial_explicit_policy: bool,
}

struct Node {
    depth: usize,
    valid_policy: ObjectIdentifier,
    expected_policy_set: BTreeSet<ObjectIdentifier>,
    parent: Option<usize>,
    alive: bool,
}

/// Process the certificate policies of a path. `certs` excludes the trust
/// anchor and is ordered anchor-issued-first … leaf-last. Returns `Err` if the
/// resulting policy state is unacceptable.
pub(crate) fn process_policies(
    certs: &[&Certificate],
    input: &PolicyInput,
) -> std::result::Result<(), String> {
    let n = certs.len();
    if n == 0 {
        return Ok(());
    }

    // §6.1.2 initialization.
    let mut nodes: Vec<Node> = vec![Node {
        depth: 0,
        valid_policy: ANY_POLICY,
        expected_policy_set: BTreeSet::from([ANY_POLICY]),
        parent: None,
        alive: true,
    }];
    let mut explicit_policy = if input.initial_explicit_policy { 0 } else { n + 1 };
    let mut policy_mapping = n + 1;
    let mut inhibit_anypolicy = n + 1;

    for (idx, cert) in certs.iter().enumerate() {
        let i = idx + 1; // 1-based depth of this certificate
        let is_last = i == n;

        // §6.1.3 (d)/(e): update the tree with this certificate's policies.
        match cert_policies(cert) {
            Some(policies) => {
                update_tree(
                    &mut nodes,
                    i,
                    &policies,
                    inhibit_anypolicy,
                    !is_last,
                    is_self_issued(cert),
                );
            }
            None => nodes.clear(), // (e) valid_policy_tree = NULL
        }
        // (f)
        if explicit_policy == 0 && tree_is_null(&nodes) {
            return Err("an explicit certificate policy is required but missing in the path".into());
        }

        if is_last {
            continue;
        }

        // §6.1.4 — prepare for the next certificate (this cert is a CA).
        // (a)(b) policy mappings.
        if let Some(maps) = policy_mappings(cert) {
            apply_mappings(&mut nodes, i, &maps, policy_mapping)?;
        }
        // (h) decrement counters for a non-self-issued certificate.
        if !is_self_issued(cert) {
            explicit_policy = explicit_policy.saturating_sub(1);
            policy_mapping = policy_mapping.saturating_sub(1);
            inhibit_anypolicy = inhibit_anypolicy.saturating_sub(1);
        }
        // (i) policy constraints.
        if let Some(pc) = policy_constraints(cert) {
            if let Some(r) = pc.require_explicit_policy {
                explicit_policy = explicit_policy.min(r as usize);
            }
            if let Some(m) = pc.inhibit_policy_mapping {
                policy_mapping = policy_mapping.min(m as usize);
            }
        }
        // (j) inhibit anyPolicy.
        if let Some(v) = inhibit_any_policy(cert) {
            inhibit_anypolicy = inhibit_anypolicy.min(v as usize);
        }
    }

    // §6.1.5 wrap-up.
    explicit_policy = explicit_policy.saturating_sub(1); // (a)
    if let Some(pc) = policy_constraints(certs[n - 1]) {
        if pc.require_explicit_policy == Some(0) {
            explicit_policy = 0; // (b)
        }
    }
    intersect_initial(&mut nodes, n, input); // (g)

    // §6.1.6 success criterion.
    if explicit_policy > 0 || !tree_is_null(&nodes) {
        Ok(())
    } else {
        Err("no acceptable certificate policy survived path validation".into())
    }
}

// --- tree operations ---------------------------------------------------------

/// §6.1.3 (d): grow the tree at depth `i` from this certificate's policies.
fn update_tree(
    nodes: &mut Vec<Node>,
    i: usize,
    policies: &BTreeSet<ObjectIdentifier>,
    inhibit_anypolicy: usize,
    not_last: bool,
    self_issued: bool,
) {
    if tree_is_null(nodes) {
        return;
    }
    let parents: Vec<usize> = alive_at(nodes, i - 1);

    // (d)(1): each explicit policy P.
    for &p in policies.iter().filter(|p| **p != ANY_POLICY) {
        let mut matched = false;
        for &pi in &parents {
            if nodes[pi].expected_policy_set.contains(&p) {
                add_child(nodes, i, p, BTreeSet::from([p]), pi);
                matched = true;
            }
        }
        // (d)(1)(ii): fall back to anyPolicy parents.
        if !matched {
            for &pi in &parents {
                if nodes[pi].expected_policy_set.contains(&ANY_POLICY) {
                    add_child(nodes, i, p, BTreeSet::from([p]), pi);
                }
            }
        }
    }

    // (d)(2): the certificate asserts anyPolicy. Processed only if anyPolicy is
    // not inhibited, or this is a non-final self-issued certificate.
    let asserts_any = policies.contains(&ANY_POLICY);
    if asserts_any && (inhibit_anypolicy > 0 || (not_last && self_issued)) {
        for &pi in &parents {
            let expected: Vec<ObjectIdentifier> =
                nodes[pi].expected_policy_set.iter().copied().collect();
            for p in expected {
                if !has_child_with_policy(nodes, pi, i, p) {
                    add_child(nodes, i, p, BTreeSet::from([p]), pi);
                }
            }
        }
    }

    prune(nodes, i);
}

/// §6.1.4 (b): apply policy mappings at depth `i`.
fn apply_mappings(
    nodes: &mut Vec<Node>,
    i: usize,
    maps: &PolicyMappings,
    policy_mapping: usize,
) -> std::result::Result<(), String> {
    // (a) anyPolicy must not be mapped.
    if maps
        .0
        .iter()
        .any(|m| m.issuer_domain_policy == ANY_POLICY || m.subject_domain_policy == ANY_POLICY)
    {
        return Err("policy mapping involves anyPolicy".into());
    }

    // Group subjectDomainPolicies by issuerDomainPolicy.
    let mut by_idp: std::collections::BTreeMap<ObjectIdentifier, BTreeSet<ObjectIdentifier>> =
        Default::default();
    for m in &maps.0 {
        by_idp
            .entry(m.issuer_domain_policy)
            .or_default()
            .insert(m.subject_domain_policy);
    }

    for (idp, sdps) in by_idp {
        if policy_mapping > 0 {
            let targets = alive_at(nodes, i)
                .into_iter()
                .filter(|&k| nodes[k].valid_policy == idp)
                .collect::<Vec<_>>();
            if !targets.is_empty() {
                for k in targets {
                    nodes[k].expected_policy_set = sdps.clone();
                }
            } else if let Some(anyk) = alive_at(nodes, i)
                .into_iter()
                .find(|&k| nodes[k].valid_policy == ANY_POLICY)
            {
                let parent = nodes[anyk].parent;
                nodes.push(Node {
                    depth: i,
                    valid_policy: idp,
                    expected_policy_set: sdps.clone(),
                    parent,
                    alive: true,
                });
            }
        } else {
            // policy_mapping == 0: delete the mapped policy.
            for k in alive_at(nodes, i) {
                if nodes[k].valid_policy == idp {
                    nodes[k].alive = false;
                }
            }
            prune(nodes, i);
        }
    }
    Ok(())
}

/// §6.1.5 (g): intersect the tree with the initial policy set. The constrained
/// policies are the nodes whose **parent is anyPolicy** (the top of each policy
/// branch); ones not in the initial set are deleted with their subtrees.
fn intersect_initial(nodes: &mut [Node], n: usize, input: &PolicyInput) {
    if tree_is_null(nodes) || input.initial_policy_set.contains(&ANY_POLICY) {
        return; // "accept any" — no constraint.
    }
    // A depth-n anyPolicy node means the path is unconstrained by policy.
    if alive_at(nodes, n)
        .iter()
        .any(|&k| nodes[k].valid_policy == ANY_POLICY)
    {
        return;
    }
    // valid_policy_node_set: alive nodes whose parent's valid_policy is anyPolicy.
    // Delete the ones not in the initial set, together with their subtrees.
    let to_kill: Vec<usize> = (0..nodes.len())
        .filter(|&k| {
            nodes[k].alive
                && nodes[k]
                    .parent
                    .is_some_and(|p| nodes[p].valid_policy == ANY_POLICY)
                && nodes[k].valid_policy != ANY_POLICY
                && !input.initial_policy_set.contains(&nodes[k].valid_policy)
        })
        .collect();
    for k in to_kill {
        kill_subtree(nodes, k);
    }
    prune(nodes, n);
}

/// Mark a node and all its descendants dead.
fn kill_subtree(nodes: &mut [Node], root: usize) {
    let mut stack = vec![root];
    while let Some(k) = stack.pop() {
        nodes[k].alive = false;
        for (c, node) in nodes.iter().enumerate() {
            if node.alive && node.parent == Some(k) {
                stack.push(c);
            }
        }
    }
}

fn add_child(
    nodes: &mut Vec<Node>,
    depth: usize,
    valid_policy: ObjectIdentifier,
    expected: BTreeSet<ObjectIdentifier>,
    parent: usize,
) {
    nodes.push(Node {
        depth,
        valid_policy,
        expected_policy_set: expected,
        parent: Some(parent),
        alive: true,
    });
}

fn alive_at(nodes: &[Node], depth: usize) -> Vec<usize> {
    (0..nodes.len())
        .filter(|&k| nodes[k].alive && nodes[k].depth == depth)
        .collect()
}

fn has_child_with_policy(nodes: &[Node], parent: usize, depth: usize, policy: ObjectIdentifier) -> bool {
    nodes.iter().any(|c| {
        c.alive && c.depth == depth && c.parent == Some(parent) && c.valid_policy == policy
    })
}

fn has_alive_child(nodes: &[Node], k: usize) -> bool {
    nodes.iter().any(|c| c.alive && c.parent == Some(k))
}

/// Remove childless internal nodes (depth < `max_depth`) until stable.
fn prune(nodes: &mut [Node], max_depth: usize) {
    loop {
        let mut changed = false;
        for k in 0..nodes.len() {
            if nodes[k].alive && nodes[k].depth < max_depth && !has_alive_child(nodes, k) {
                nodes[k].alive = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn tree_is_null(nodes: &[Node]) -> bool {
    !nodes.iter().any(|node| node.alive)
}

// --- extension accessors -----------------------------------------------------

fn cert_policies(cert: &Certificate) -> Option<BTreeSet<ObjectIdentifier>> {
    match cert.tbs_certificate.get::<CertificatePolicies>() {
        Ok(Some((_, pols))) => Some(pols.0.iter().map(|p| p.policy_identifier).collect()),
        _ => None,
    }
}

fn policy_mappings(cert: &Certificate) -> Option<PolicyMappings> {
    cert.tbs_certificate.get::<PolicyMappings>().ok().flatten().map(|(_, m)| m)
}

fn policy_constraints(cert: &Certificate) -> Option<PolicyConstraints> {
    cert.tbs_certificate.get::<PolicyConstraints>().ok().flatten().map(|(_, c)| c)
}

fn inhibit_any_policy(cert: &Certificate) -> Option<u32> {
    cert.tbs_certificate
        .get::<InhibitAnyPolicy>()
        .ok()
        .flatten()
        .map(|(_, v)| v.0)
}

pub(crate) fn is_self_issued(cert: &Certificate) -> bool {
    matches!(
        (
            cert.tbs_certificate.subject.to_der(),
            cert.tbs_certificate.issuer.to_der(),
        ),
        (Ok(s), Ok(i)) if s == i
    )
}
