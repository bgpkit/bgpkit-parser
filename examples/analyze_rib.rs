use bgpkit_parser::models::*;
use bgpkit_parser::parser::BgpkitParser;
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "rib.20260421.2000.bz2".to_string());

    println!("Analyzing {}...", file);

    let mut stats = Stats::default();

    for record in BgpkitParser::new(&file).unwrap().into_record_iter() {
        stats.total_records += 1;

        // Extract BGP UPDATE from MRT record
        match &record.message {
            MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(msg)) => {
                // Access the BGP message
                if let BgpMessage::Update(update) = &msg.bgp_message {
                    analyze_update(&mut stats, update);
                }
            }
            MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)) => {
                // For TableDumpV2 RIB entries, analyze each entry's attributes
                for entry in &rib.rib_entries {
                    analyze_attributes(&mut stats, &entry.attributes);
                }
            }
            _ => {}
        }

        // Progress indicator
        if stats.total_records % 10000 == 0 {
            println!("Processed {} records...", stats.total_records);
        }

        // Limit to avoid taking too long (sample first 200k records)
        if stats.total_records >= 200000 {
            println!("Sampling complete (first 200k records)");
            break;
        }
    }

    stats.print_report();
}

fn analyze_update(stats: &mut Stats, update: &BgpUpdateMessage) {
    stats.total_updates += 1;

    // Count withdrawn prefixes
    let withdrawn_count = update.withdrawn_prefixes.len();
    *stats
        .withdrawn_per_update
        .entry(withdrawn_count)
        .or_insert(0) += 1;

    // Count announced prefixes (traditional)
    let announced_count = update.announced_prefixes.len();
    *stats
        .announced_per_update
        .entry(announced_count)
        .or_insert(0) += 1;

    // Analyze attributes
    analyze_attributes(stats, &update.attributes);
}

fn analyze_attributes(stats: &mut Stats, attributes: &Attributes) {
    // Use the public APIs to access attributes
    if let Some(path) = attributes.as_path() {
        stats.routes_with_aspath += 1;
        let segment_count = path.segments.len();
        *stats.as_path_segments.entry(segment_count).or_insert(0) += 1;

        for segment in &path.segments {
            let asn_count = segment.len();
            *stats.asns_per_segment.entry(asn_count).or_insert(0) += 1;

            match segment {
                AsPathSegment::AsSequence(_) => {
                    stats.sequence_segments += 1;
                }
                AsPathSegment::AsSet(_) => {
                    stats.set_segments += 1;
                }
                _ => {}
            }
        }
    }

    // Count communities using iterator
    let community_count: usize = attributes.iter_communities().count();
    if community_count > 0 {
        *stats.communities_count.entry(community_count).or_insert(0) += 1;
    }

    // Check for other attributes by iterating
    // Note: Attributes::iter() yields &AttributeValue directly
    for value in attributes.iter() {
        match value {
            AttributeValue::ExtendedCommunities(ext_comm) => {
                let count = ext_comm.len();
                *stats.ext_communities_count.entry(count).or_insert(0) += 1;
            }
            AttributeValue::LargeCommunities(large_comm) => {
                let count = large_comm.len();
                *stats.large_communities_count.entry(count).or_insert(0) += 1;
            }
            AttributeValue::Clusters(clusters) => {
                let count = clusters.len();
                *stats.cluster_list_size.entry(count).or_insert(0) += 1;
            }
            AttributeValue::MpReachNlri(nlri) => {
                stats.mp_reach_nlri += 1;
                let prefix_count = nlri.prefixes.len();
                *stats.prefixes_per_nlri.entry(prefix_count).or_insert(0) += 1;

                if let Some(ref labeled) = nlri.labeled_prefixes {
                    let count = labeled.len();
                    *stats.labeled_prefixes_per_nlri.entry(count).or_insert(0) += 1;
                }
            }
            AttributeValue::MpUnreachNlri(nlri) => {
                stats.mp_unreach_nlri += 1;
                let prefix_count = nlri.prefixes.len();
                *stats.mp_withdrawn_per_nlri.entry(prefix_count).or_insert(0) += 1;
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Stats {
    total_records: u64,
    total_updates: u64,
    routes_with_aspath: u64,
    mp_reach_nlri: u64,
    mp_unreach_nlri: u64,
    sequence_segments: u64,
    set_segments: u64,

    withdrawn_per_update: HashMap<usize, u64>,
    announced_per_update: HashMap<usize, u64>,
    prefixes_per_nlri: HashMap<usize, u64>,
    mp_withdrawn_per_nlri: HashMap<usize, u64>,
    labeled_prefixes_per_nlri: HashMap<usize, u64>,
    communities_count: HashMap<usize, u64>,
    ext_communities_count: HashMap<usize, u64>,
    large_communities_count: HashMap<usize, u64>,
    as_path_segments: HashMap<usize, u64>,
    asns_per_segment: HashMap<usize, u64>,
    cluster_list_size: HashMap<usize, u64>,
}

impl Stats {
    fn print_report(&self) {
        println!("\n========== ANALYSIS REPORT ==========\n");
        println!("Total MRT records analyzed: {}", self.total_records);
        println!("BGP UPDATE/RIB entries: {}", self.total_updates);
        println!("Routes with AS_PATH: {}", self.routes_with_aspath);
        println!("MP_REACH_NLRI attributes: {}", self.mp_reach_nlri);
        println!("MP_UNREACH_NLRI attributes: {}", self.mp_unreach_nlri);
        println!("AS_SEQUENCE segments: {}", self.sequence_segments);
        println!("AS_SET segments: {}", self.set_segments);

        println!("\n--- Withdrawn Prefixes per UPDATE ---");
        self.print_distribution(&self.withdrawn_per_update, self.total_updates);

        println!("\n--- Announced Prefixes per UPDATE (traditional) ---");
        self.print_distribution(&self.announced_per_update, self.total_updates);

        println!("\n--- Prefixes per MP_REACH_NLRI ---");
        self.print_distribution(&self.prefixes_per_nlri, self.mp_reach_nlri);

        if !self.labeled_prefixes_per_nlri.is_empty() {
            println!("\n--- Labeled Prefixes per MP_REACH_NLRI (SAFI 4) ---");
            let total: u64 = self.labeled_prefixes_per_nlri.values().sum();
            self.print_distribution(&self.labeled_prefixes_per_nlri, total);
        } else {
            println!("\n--- Labeled Prefixes per MP_REACH_NLRI (SAFI 4) ---");
            println!("  No MPLS-labeled prefixes found in sample");
        }

        println!("\n--- Communities per Route ---");
        let total_with_comm: u64 = self.communities_count.values().sum();
        self.print_distribution(&self.communities_count, total_with_comm);

        println!("\n--- Extended Communities per Route ---");
        let total_with_ext: u64 = self.ext_communities_count.values().sum();
        self.print_distribution(&self.ext_communities_count, total_with_ext);

        println!("\n--- Large Communities per Route ---");
        let total_with_large: u64 = self.large_communities_count.values().sum();
        self.print_distribution(&self.large_communities_count, total_with_large);

        println!("\n--- AS Path Segments per Route ---");
        self.print_distribution(&self.as_path_segments, self.routes_with_aspath);

        println!("\n--- ASNs per AS Path Segment ---");
        let total_segments = self.sequence_segments + self.set_segments;
        self.print_distribution(&self.asns_per_segment, total_segments);

        println!("\n--- Cluster List Size ---");
        let total_with_clusters: u64 = self.cluster_list_size.values().sum();
        self.print_distribution(&self.cluster_list_size, total_with_clusters);

        println!("\n========== SMALLVEC RECOMMENDATIONS ==========\n");
        self.print_recommendations();
    }

    fn print_distribution(&self, dist: &HashMap<usize, u64>, total: u64) {
        if total == 0 {
            println!("  No data");
            return;
        }

        let mut sorted: Vec<_> = dist.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);

        let mut cumulative = 0u64;
        for (count, freq) in sorted.iter().take(10) {
            cumulative += **freq;
            let pct = (**freq as f64 / total as f64) * 100.0;
            let cum_pct = (cumulative as f64 / total as f64) * 100.0;
            println!(
                "  {:3}: {:8} ({:5.2}%, cum: {:5.2}%)",
                count, freq, pct, cum_pct
            );
        }

        if sorted.len() > 10 {
            let remaining: u64 = sorted.iter().skip(10).map(|(_, v)| **v).sum();
            cumulative += remaining;
            let pct = (remaining as f64 / total as f64) * 100.0;
            let cum_pct = (cumulative as f64 / total as f64) * 100.0;
            println!(
                "  >10: {:8} ({:5.2}%, cum: {:5.2}%)",
                remaining, pct, cum_pct
            );
        }
    }

    fn print_recommendations(&self) {
        println!("Based on the distribution:\n");

        // ASNs per segment
        let total_segments = self.sequence_segments + self.set_segments;
        if total_segments > 0 {
            let covered_by_4 = self.cumulative_count(&self.asns_per_segment, 4);
            let covered_by_6 = self.cumulative_count(&self.asns_per_segment, 6);
            let covered_by_8 = self.cumulative_count(&self.asns_per_segment, 8);
            println!(
                "ASNs per AS Path Segment (total segments: {}):",
                total_segments
            );
            println!(
                "  - Inline [Asn; 4]: covers {:6.2}% of segments",
                (covered_by_4 as f64 / total_segments as f64) * 100.0
            );
            println!(
                "  - Inline [Asn; 6]: covers {:6.2}% of segments",
                (covered_by_6 as f64 / total_segments as f64) * 100.0
            );
            println!(
                "  - Inline [Asn; 8]: covers {:6.2}% of segments",
                (covered_by_8 as f64 / total_segments as f64) * 100.0
            );
        }

        // AS Path Segments per route
        if self.routes_with_aspath > 0 {
            let covered_by_2 = self.cumulative_count(&self.as_path_segments, 2);
            let covered_by_4 = self.cumulative_count(&self.as_path_segments, 4);
            println!(
                "\nAS Path Segments per route (routes with AS_PATH: {}):",
                self.routes_with_aspath
            );
            println!(
                "  - Inline [AsPathSegment; 2]: covers {:6.2}% of routes",
                (covered_by_2 as f64 / self.routes_with_aspath as f64) * 100.0
            );
            println!(
                "  - Inline [AsPathSegment; 4]: covers {:6.2}% of routes",
                (covered_by_4 as f64 / self.routes_with_aspath as f64) * 100.0
            );
        }

        // Communities
        let total_with_comm: u64 = self.communities_count.values().sum();
        if total_with_comm > 0 {
            let covered_by_4 = self.cumulative_count(&self.communities_count, 4);
            let covered_by_6 = self.cumulative_count(&self.communities_count, 6);
            println!(
                "\nCommunities per route (routes with communities: {}):",
                total_with_comm
            );
            println!(
                "  - Inline [Community; 4]: covers {:6.2}% of routes",
                (covered_by_4 as f64 / total_with_comm as f64) * 100.0
            );
            println!(
                "  - Inline [Community; 6]: covers {:6.2}% of routes",
                (covered_by_6 as f64 / total_with_comm as f64) * 100.0
            );
        }

        // Prefixes per MP_REACH_NLRI
        if self.mp_reach_nlri > 0 {
            let covered_by_1 = self.cumulative_count(&self.prefixes_per_nlri, 1);
            let covered_by_2 = self.cumulative_count(&self.prefixes_per_nlri, 2);
            println!(
                "\nPrefixes per MP_REACH_NLRI (total: {}):",
                self.mp_reach_nlri
            );
            println!(
                "  - Inline [NetworkPrefix; 1]: covers {:6.2}% of NLRIs",
                (covered_by_1 as f64 / self.mp_reach_nlri as f64) * 100.0
            );
            println!(
                "  - Inline [NetworkPrefix; 2]: covers {:6.2}% of NLRIs",
                (covered_by_2 as f64 / self.mp_reach_nlri as f64) * 100.0
            );
        }

        // Extended communities
        let total_with_ext: u64 = self.ext_communities_count.values().sum();
        if total_with_ext > 0 {
            let covered_by_2 = self.cumulative_count(&self.ext_communities_count, 2);
            let covered_by_4 = self.cumulative_count(&self.ext_communities_count, 4);
            println!(
                "\nExtended Communities per route (routes with ext communities: {}):",
                total_with_ext
            );
            println!(
                "  - Inline [ExtendedCommunity; 2]: covers {:6.2}%",
                (covered_by_2 as f64 / total_with_ext as f64) * 100.0
            );
            println!(
                "  - Inline [ExtendedCommunity; 4]: covers {:6.2}%",
                (covered_by_4 as f64 / total_with_ext as f64) * 100.0
            );
        }

        // Large communities
        let total_with_large: u64 = self.large_communities_count.values().sum();
        if total_with_large > 0 {
            let covered_by_2 = self.cumulative_count(&self.large_communities_count, 2);
            let covered_by_4 = self.cumulative_count(&self.large_communities_count, 4);
            println!(
                "\nLarge Communities per route (routes with large communities: {}):",
                total_with_large
            );
            println!(
                "  - Inline [LargeCommunity; 2]: covers {:6.2}%",
                (covered_by_2 as f64 / total_with_large as f64) * 100.0
            );
            println!(
                "  - Inline [LargeCommunity; 4]: covers {:6.2}%",
                (covered_by_4 as f64 / total_with_large as f64) * 100.0
            );
        }

        // Cluster list
        let total_with_clusters: u64 = self.cluster_list_size.values().sum();
        if total_with_clusters > 0 {
            let covered_by_2 = self.cumulative_count(&self.cluster_list_size, 2);
            let covered_by_4 = self.cumulative_count(&self.cluster_list_size, 4);
            println!(
                "\nCluster list size (routes with cluster list: {}):",
                total_with_clusters
            );
            println!(
                "  - Inline [u32; 2]: covers {:6.2}% of routes",
                (covered_by_2 as f64 / total_with_clusters as f64) * 100.0
            );
            println!(
                "  - Inline [u32; 4]: covers {:6.2}% of routes",
                (covered_by_4 as f64 / total_with_clusters as f64) * 100.0
            );
        }

        // Withdrawn/Announced per UPDATE (traditional)
        if self.total_updates > 0 {
            let covered_by_1 = self.cumulative_count(&self.withdrawn_per_update, 1);
            let covered_by_2 = self.cumulative_count(&self.announced_per_update, 2);
            println!("\nTraditional UPDATE messages:");
            println!(
                "  - Withdrawn [NetworkPrefix; 1]: covers {:6.2}% of UPDATEs",
                (covered_by_1 as f64 / self.total_updates as f64) * 100.0
            );
            println!(
                "  - Announced [NetworkPrefix; 2]: covers {:6.2}% of UPDATEs",
                (covered_by_2 as f64 / self.total_updates as f64) * 100.0
            );
        }
    }

    fn cumulative_count(&self, dist: &HashMap<usize, u64>, max_size: usize) -> u64 {
        dist.iter()
            .filter(|(k, _)| **k <= max_size)
            .map(|(_, v)| *v)
            .sum()
    }
}
