#include <algorithm>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ============================================================
// 1. Basic data structures
// ============================================================

enum class RRType : uint8_t {
    A, AAAA, NS, CNAME, DNAME, MX, TXT, SOA, PTR, SRV, OTHER
};

struct Record {
    int server;
    int zone;
    int name;
    RRType type;
    int data;
    size_t id;
};

struct ErrorItem {
    std::string dimension;
    std::string entity;
    std::string msg;
};

struct PairHash {
    size_t operator()(const std::pair<int, int>& p) const {
        return (static_cast<size_t>(static_cast<uint32_t>(p.first)) << 32) ^
               static_cast<size_t>(static_cast<uint32_t>(p.second));
    }
};

using Context = std::pair<int, int>; // (server, zone)

static inline uint64_t make_addr_key(RRType t, int data) {
    return (static_cast<uint64_t>(static_cast<uint8_t>(t)) << 32) ^
           static_cast<uint32_t>(data);
}

// ============================================================
// 2. String interning
// ============================================================

class StringPool {
public:
    int intern(const std::string& s) {
        auto it = id_.find(s);
        if (it != id_.end()) return it->second;

        int nid = static_cast<int>(str_.size());
        str_.push_back(s);
        id_[s] = nid;
        return nid;
    }

    const std::string& get(int id) const {
        return str_[id];
    }

    std::optional<int> find(const std::string& s) const {
        auto it = id_.find(s);
        if (it == id_.end()) return std::nullopt;
        return it->second;
    }

    size_t size() const {
        return str_.size();
    }

    void reserve(size_t n) {
        str_.reserve(n);
        id_.reserve(n);
    }

private:
    std::vector<std::string> str_;
    std::unordered_map<std::string, int> id_;
};

// ============================================================
// 3. Domain utilities
// ============================================================

static std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = char(c | 0x20);
    }
    return s;
}

static std::string normalize_domain(std::string s) {
    s = to_lower_ascii(s);

    if (!s.empty() && s.back() != '.' && s.find(':') == std::string::npos) {
        s.push_back('.');
    }

    return s;
}

static bool ends_with(std::string_view s, std::string_view suffix) {
    if (suffix.size() > s.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

static bool is_descendant_str(const std::string& child,
                              const std::string& ancestor) {
    if (child == ancestor) return false;
    if (ancestor == ".") return child != ".";

    std::string suffix = "." + ancestor;
    return ends_with(child, suffix);
}

static std::optional<std::string> parent_str(const std::string& n) {
    if (n == ".") return std::nullopt;

    auto pos = n.find('.');
    if (pos == std::string::npos || pos + 1 >= n.size()) {
        return std::make_optional<std::string>(".");
    }

    return n.substr(pos + 1);
}

static bool is_wildcard_str(const std::string& n) {
    return n.size() > 2 && n[0] == '*' && n[1] == '.';
}

static std::optional<std::string> wildcard_encloser_str(const std::string& n) {
    if (!is_wildcard_str(n)) return std::nullopt;
    return n.substr(2);
}

static RRType parse_type(const std::string& t) {
    if (t == "A") return RRType::A;
    if (t == "AAAA") return RRType::AAAA;
    if (t == "NS") return RRType::NS;
    if (t == "CNAME") return RRType::CNAME;
    if (t == "DNAME") return RRType::DNAME;
    if (t == "MX") return RRType::MX;
    if (t == "TXT") return RRType::TXT;
    if (t == "SOA") return RRType::SOA;
    if (t == "PTR") return RRType::PTR;
    if (t == "SRV") return RRType::SRV;
    return RRType::OTHER;
}

static std::string type_to_string(RRType t) {
    switch (t) {
        case RRType::A: return "A";
        case RRType::AAAA: return "AAAA";
        case RRType::NS: return "NS";
        case RRType::CNAME: return "CNAME";
        case RRType::DNAME: return "DNAME";
        case RRType::MX: return "MX";
        case RRType::TXT: return "TXT";
        case RRType::SOA: return "SOA";
        case RRType::PTR: return "PTR";
        case RRType::SRV: return "SRV";
        default: return "OTHER";
    }
}

static bool is_terminal_type(RRType t) {
    return t == RRType::A ||
           t == RRType::AAAA ||
           t == RRType::MX ||
           t == RRType::TXT;
}

static bool rdata_is_domain_name(RRType t) {
    return t == RRType::NS ||
           t == RRType::CNAME ||
           t == RRType::DNAME ||
           t == RRType::MX ||
           t == RRType::PTR ||
           t == RRType::SRV;
}

// ============================================================
// 4. GraphDNS verifier
// ============================================================

class GraphVerifier {
public:
    explicit GraphVerifier(const std::string& fact_path) {
        load_facts(fact_path);
        build_original_indices();
    }

    void run() {
        detect_shadow_records();
        build_clean_indices();
        construct_semantic_adjacency();
        verify_all();
    }

    void write_outputs(const std::string& error_path) const {
        std::ofstream out(error_path);
        if (!out.is_open()) {
            throw std::runtime_error("Cannot write output file: " + error_path);
        }

        out << "dimension\tentity\tmessage\n";
        for (const auto& e : errors_) {
            out << e.dimension << "\t" << e.entity << "\t" << e.msg << "\n";
        }
    }

private:
    StringPool pool_;

    std::vector<Record> records_;
    std::vector<int> clean_records_;

    std::unordered_set<size_t> shadow_;
    std::unordered_set<size_t> glue_records_;

    std::unordered_map<Context, std::vector<int>, PairHash> records_by_ctx_;
    std::unordered_map<Context, std::vector<int>, PairHash> clean_by_ctx_;
    std::unordered_map<Context, std::vector<int>, PairHash> deleg_ns_by_ctx_;

    std::unordered_set<Context, PairHash> contexts_;
    std::unordered_set<int> server_ids_;

    // zone apex -> contexts hosting this zone
    std::unordered_map<int, std::vector<Context>> zone_to_contexts_;

    // ctx -> explicit clean owner names
    std::unordered_map<Context, std::unordered_set<int>, PairHash> explicit_clean_;

    // ctx -> wildcard encloser -> wildcard owner
    std::unordered_map<Context, std::unordered_map<int, int>, PairHash> wildcard_by_encloser_;

    // ctx -> non-apex NS owner cuts
    std::unordered_map<Context, std::unordered_set<int>, PairHash> ns_cuts_;

    // ctx -> DNAME owners
    std::unordered_map<Context, std::unordered_set<int>, PairHash> dname_owners_;

    // Fast semantic indices
    std::unordered_set<int> terminal_names_;
    std::unordered_set<Context, PairHash> soa_index_;

    // (zone, name) -> A/AAAA values
    std::unordered_map<std::pair<int, int>,
                       std::unordered_set<uint64_t>,
                       PairHash> addr_index_;

    // name -> all ancestor ids that already exist in the pool
    mutable std::vector<std::vector<int>> ancestor_cache_;
    mutable std::vector<uint8_t> ancestor_cache_ready_;

    // name -> closest authoritative contexts
    mutable std::vector<std::vector<Context>> closest_ctx_cache_;
    mutable std::vector<uint8_t> closest_ctx_cache_ready_;

    // ancestor -> descendant names among all configured names
    std::unordered_map<int, std::vector<int>> descendants_by_ancestor_;

    // rewrite adjacency: owner/source name -> matched continuation name
    std::unordered_map<int, std::vector<int>> alias_adj_;

    // NS dependency graph: server -> (target server, child zone)
    std::unordered_map<int, std::vector<std::pair<int, int>>> ns_dep_adj_;

    // DNAME target-root -> target-side descendant names
    std::unordered_map<int, std::vector<int>> dname_target_rewrite_adj_;

    // terminal reachability cache for alias graph
    mutable std::unordered_map<int, bool> terminal_reach_cache_;

    std::vector<int> all_names_;
    std::vector<ErrorItem> errors_;

private:
    // ------------------------------------------------------------
    // Loading
    // Input format:
    // server<TAB>zone<TAB>name<TAB>type<TAB>data
    // ------------------------------------------------------------

    void load_facts(const std::string& fact_path) {
        std::ifstream in(fact_path);
        if (!in.is_open()) {
            throw std::runtime_error("Cannot open fact file: " + fact_path);
        }

        records_.reserve(1 << 20);
        pool_.reserve(1 << 20);

        std::string line;
        size_t id = 0;

        while (std::getline(in, line)) {
            if (line.empty()) continue;

            std::string_view cols[5];
            if (!split_tab5(line, cols)) continue;

            std::string server = normalize_domain(std::string(cols[0]));
            std::string zone   = normalize_domain(std::string(cols[1]));
            std::string name   = normalize_domain(std::string(cols[2]));
            std::string type_s(cols[3]);
            std::string data(cols[4]);

            RRType type = parse_type(type_s);

            if (rdata_is_domain_name(type)) {
                data = normalize_domain(data);
            }

            Record r;
            r.server = pool_.intern(server);
            r.zone   = pool_.intern(zone);
            r.name   = pool_.intern(name);
            r.type   = type;
            r.data   = pool_.intern(data);
            r.id     = id++;

            records_.push_back(r);
        }
    }

    static bool split_tab5(const std::string& line, std::string_view cols[5]) {
        size_t start = 0;

        for (int i = 0; i < 4; ++i) {
            size_t pos = line.find('\t', start);
            if (pos == std::string::npos) return false;

            cols[i] = std::string_view(line.data() + start, pos - start);
            start = pos + 1;
        }

        cols[4] = std::string_view(line.data() + start, line.size() - start);
        return true;
    }

    // ------------------------------------------------------------
    // Original indices
    // ------------------------------------------------------------

    void build_original_indices() {
        records_by_ctx_.reserve(records_.size() / 4 + 1);
        contexts_.reserve(records_.size() / 16 + 1);
        server_ids_.reserve(records_.size() / 64 + 1);
        zone_to_contexts_.reserve(records_.size() / 64 + 1);

        std::unordered_set<int> all_name_set;
        all_name_set.reserve(records_.size() * 2);

        for (int i = 0; i < static_cast<int>(records_.size()); ++i) {
            const auto& r = records_[i];

            server_ids_.insert(r.server);

            Context ctx{r.server, r.zone};
            contexts_.insert(ctx);
            records_by_ctx_[ctx].push_back(i);

            all_name_set.insert(r.name);

            if (rdata_is_domain_name(r.type)) {
                all_name_set.insert(r.data);
            }

            if (r.type == RRType::SOA && r.name == r.zone) {
                zone_to_contexts_[r.zone].push_back(ctx);
            }
        }

        all_names_.assign(all_name_set.begin(), all_name_set.end());

        compute_glue_records();
        compute_cut_indices();
        build_descendant_index();
    }

    void compute_cut_indices() {
        ns_cuts_.reserve(records_by_ctx_.size());
        dname_owners_.reserve(records_by_ctx_.size());

        for (const auto& [ctx, ids] : records_by_ctx_) {
            for (int rid : ids) {
                const auto& r = records_[rid];

                if (r.type == RRType::NS && r.name != r.zone) {
                    ns_cuts_[ctx].insert(r.name);
                }

                if (r.type == RRType::DNAME) {
                    dname_owners_[ctx].insert(r.name);
                }
            }
        }
    }

    void compute_glue_records() {
        glue_records_.reserve(records_.size() / 16 + 1);

        for (const auto& [ctx, ids] : records_by_ctx_) {
            int zone = ctx.second;

            std::unordered_set<int> ns_targets;
            ns_targets.reserve(ids.size() / 8 + 1);

            for (int rid : ids) {
                const auto& r = records_[rid];

                if (r.type == RRType::NS && r.name != r.zone) {
                    if (in_zone(r.data, zone)) {
                        ns_targets.insert(r.data);
                    }
                }
            }

            if (ns_targets.empty()) continue;

            for (int rid : ids) {
                const auto& r = records_[rid];

                if ((r.type == RRType::A || r.type == RRType::AAAA) &&
                    ns_targets.find(r.name) != ns_targets.end()) {
                    glue_records_.insert(r.id);
                }
            }
        }
    }

    void build_descendant_index() {
        descendants_by_ancestor_.reserve(all_names_.size());

        for (int name : all_names_) {
            const auto& ancestors = get_ancestors(name);
            for (int anc : ancestors) {
                descendants_by_ancestor_[anc].push_back(name);
            }
        }
    }

    // ------------------------------------------------------------
    // Ancestor and closest-context caches
    // ------------------------------------------------------------

    void ensure_ancestor_cache_size() const {
        size_t n = pool_.size();

        if (ancestor_cache_.size() < n) {
            ancestor_cache_.resize(n);
            ancestor_cache_ready_.resize(n, 0);
        }

        if (closest_ctx_cache_.size() < n) {
            closest_ctx_cache_.resize(n);
            closest_ctx_cache_ready_.resize(n, 0);
        }
    }

    const std::vector<int>& get_ancestors(int name) const {
        ensure_ancestor_cache_size();

        if (name >= 0 &&
            name < static_cast<int>(ancestor_cache_ready_.size()) &&
            ancestor_cache_ready_[name]) {
            return ancestor_cache_[name];
        }

        auto& out = ancestor_cache_[name];
        out.clear();

        std::string cur = pool_.get(name);

        while (true) {
            auto p = parent_str(cur);
            if (!p.has_value()) break;

            auto pid = pool_.find(*p);
            if (pid.has_value()) {
                out.push_back(*pid);
            }

            if (*p == ".") break;
            cur = *p;
        }

        ancestor_cache_ready_[name] = 1;
        return out;
    }

    const std::vector<Context>& closest_contexts_for_name_cached(int target) const {
        ensure_ancestor_cache_size();

        if (target >= 0 &&
            target < static_cast<int>(closest_ctx_cache_ready_.size()) &&
            closest_ctx_cache_ready_[target]) {
            return closest_ctx_cache_[target];
        }

        auto& out = closest_ctx_cache_[target];
        out.clear();

        std::string cur = pool_.get(target);

        while (true) {
            auto zid = pool_.find(cur);
            if (zid.has_value()) {
                auto it = zone_to_contexts_.find(*zid);
                if (it != zone_to_contexts_.end()) {
                    out = it->second;
                    break;
                }
            }

            auto p = parent_str(cur);
            if (!p.has_value()) break;
            if (*p == cur) break;

            cur = *p;
        }

        closest_ctx_cache_ready_[target] = 1;
        return out;
    }

    // ------------------------------------------------------------
    // Shadow detection and clean indices
    // ------------------------------------------------------------

    void detect_shadow_records() {
        shadow_.reserve(records_.size() / 16 + 1);

        for (const auto& [ctx, ids] : records_by_ctx_) {
            auto ns_it = ns_cuts_.find(ctx);
            auto dn_it = dname_owners_.find(ctx);

            const std::unordered_set<int>* ns_set =
                (ns_it == ns_cuts_.end()) ? nullptr : &ns_it->second;

            const std::unordered_set<int>* dn_set =
                (dn_it == dname_owners_.end()) ? nullptr : &dn_it->second;

            for (int rid : ids) {
                const auto& r = records_[rid];

                bool occ_ns = ns_set && has_ancestor_in_set_cached(r.name, *ns_set);
                bool occ_d  = dn_set && has_ancestor_in_set_cached(r.name, *dn_set);

                if (occ_ns &&
                    glue_records_.find(r.id) == glue_records_.end()) {
                    shadow_.insert(r.id);
                    add_error("Shadow_Record",
                              r.name,
                              "Occluded by NS delegation");
                }

                if (occ_d && r.type != RRType::DNAME) {
                    shadow_.insert(r.id);
                    add_error("Shadow_Record",
                              r.name,
                              "Occluded by DNAME subtree rewrite");
                }
            }
        }
    }

    bool has_ancestor_in_set_cached(int name,
                                    const std::unordered_set<int>& ancestors) const {
        const auto& vec = get_ancestors(name);

        for (int anc : vec) {
            if (ancestors.find(anc) != ancestors.end()) {
                return true;
            }
        }

        return false;
    }

    void build_clean_indices() {
        clean_records_.reserve(records_.size());
        clean_by_ctx_.reserve(records_by_ctx_.size());
        deleg_ns_by_ctx_.reserve(records_by_ctx_.size());
        explicit_clean_.reserve(records_by_ctx_.size());
        wildcard_by_encloser_.reserve(records_by_ctx_.size());

        terminal_names_.reserve(records_.size() / 8 + 1);
        addr_index_.reserve(records_.size() / 4 + 1);
        soa_index_.reserve(records_.size() / 64 + 1);

        for (int i = 0; i < static_cast<int>(records_.size()); ++i) {
            const auto& r = records_[i];

            if (shadow_.find(r.id) != shadow_.end()) continue;

            clean_records_.push_back(i);

            Context ctx{r.server, r.zone};

            clean_by_ctx_[ctx].push_back(i);
            explicit_clean_[ctx].insert(r.name);

            if (r.type == RRType::NS && r.name != r.zone) {
                deleg_ns_by_ctx_[ctx].push_back(i);
            }

            if (is_terminal_type(r.type)) {
                terminal_names_.insert(r.name);
            }

            if (r.type == RRType::A || r.type == RRType::AAAA) {
                addr_index_[{r.zone, r.name}].insert(make_addr_key(r.type, r.data));
            }

            if (r.type == RRType::SOA && r.name == r.zone) {
                soa_index_.insert({r.server, r.zone});
            }

            if (is_wildcard_str(pool_.get(r.name))) {
                auto e = wildcard_encloser_str(pool_.get(r.name));
                if (e.has_value()) {
                    int eid = pool_.intern(*e);
                    wildcard_by_encloser_[ctx][eid] = r.name;
                }
            }
        }
    }

    // ------------------------------------------------------------
    // Domain / context matching
    // ------------------------------------------------------------

    bool in_zone(int name, int zone) const {
        const auto& n = pool_.get(name);
        const auto& z = pool_.get(zone);

        return n == z || is_descendant_str(n, z);
    }

    std::optional<int> exact_or_wildcard_match(Context ctx,
                                               int query) const {
        auto eit = explicit_clean_.find(ctx);
        if (eit != explicit_clean_.end() &&
            eit->second.find(query) != eit->second.end()) {
            return query;
        }

        auto p = parent_str(pool_.get(query));
        if (!p.has_value()) return std::nullopt;

        auto pid = pool_.find(*p);
        if (!pid.has_value()) return std::nullopt;

        auto wit = wildcard_by_encloser_.find(ctx);
        if (wit == wildcard_by_encloser_.end()) return std::nullopt;

        auto hit = wit->second.find(*pid);
        if (hit == wit->second.end()) return std::nullopt;

        return hit->second;
    }

    bool belongs_to_configured_zone(int name) const {
        return !closest_contexts_for_name_cached(name).empty();
    }

    // ------------------------------------------------------------
    // Semantic adjacency construction
    // ------------------------------------------------------------

    void construct_semantic_adjacency() {
        construct_cname_adjacency();
        construct_dname_adjacency();
        construct_ns_dependency_adjacency();
    }

    void construct_cname_adjacency() {
        alias_adj_.reserve(clean_records_.size() / 32 + 1);

        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::CNAME) continue;

            const auto& contexts = closest_contexts_for_name_cached(r.data);

            for (Context ctx : contexts) {
                auto matched = exact_or_wildcard_match(ctx, r.data);
                if (!matched.has_value()) continue;

                alias_adj_[r.name].push_back(*matched);
            }
        }
    }

    void construct_dname_adjacency() {
        dname_target_rewrite_adj_.reserve(clean_records_.size() / 64 + 1);

        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::DNAME) continue;

            int owner = r.name;
            int target_root = r.data;

            // Old behavior preserved:
            // target_root -> explicit descendants under target_root in closest target zone.
            const auto& target_contexts = closest_contexts_for_name_cached(target_root);

            for (Context ctx : target_contexts) {
                auto cit = clean_by_ctx_.find(ctx);
                if (cit == clean_by_ctx_.end()) continue;

                auto& dsts = dname_target_rewrite_adj_[target_root];

                for (int crid : cit->second) {
                    const auto& cr = records_[crid];

                    if (is_descendant_str(pool_.get(cr.name),
                                          pool_.get(target_root))) {
                        dsts.push_back(cr.name);
                    }
                }
            }

            // Optimized concrete query-path DNAME rewriting:
            // only names under DNAME owner are considered.
            auto dit = descendants_by_ancestor_.find(owner);
            if (dit == descendants_by_ancestor_.end()) continue;

            for (int src : dit->second) {
                int rewritten = dname_rewrite(src, owner, target_root);

                if (static_cast<int>(pool_.get(rewritten).size()) > 255) {
                    add_error("No_Query_Exceeds_Maximum_Length",
                              src,
                              "Query exceeds 255 bytes after DNAME rewrite");
                }

                const auto& contexts = closest_contexts_for_name_cached(rewritten);

                for (Context ctx : contexts) {
                    auto matched = exact_or_wildcard_match(ctx, rewritten);
                    if (!matched.has_value()) continue;

                    alias_adj_[src].push_back(*matched);
                }
            }
        }
    }

    int dname_rewrite(int src, int owner, int target_root) {
        const std::string& s = pool_.get(src);
        const std::string& o = pool_.get(owner);
        const std::string& t = pool_.get(target_root);

        std::string prefix = s.substr(0, s.size() - o.size());
        return pool_.intern(prefix + t);
    }

    void construct_ns_dependency_adjacency() {
        ns_dep_adj_.reserve(clean_records_.size() / 32 + 1);

        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS || r.name == r.zone) continue;

            int parent_server = r.server;
            int child = r.name;
            int ns_target = r.data;

            ns_dep_adj_[parent_server].push_back({ns_target, child});
        }
    }

    // ------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------

    void verify_all() {
        verify_orphan_records();
        verify_lame_delegation();
        verify_delegation_consistency();
        verify_missing_glue();
        verify_cyclic_zone_dependency();
        verify_rewrite_loops();
        verify_rewrite_blackholing();
    }

    void verify_orphan_records() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (!(r.type == RRType::A || r.type == RRType::AAAA)) {
                continue;
            }

            Context ctx{r.server, r.zone};

            auto dit = deleg_ns_by_ctx_.find(ctx);
            if (dit == deleg_ns_by_ctx_.end()) continue;

            bool anchored = false;

            for (int nrid : dit->second) {
                const auto& nsr = records_[nrid];

                if (r.name == nsr.data ||
                    r.name == nsr.name ||
                    is_descendant_str(pool_.get(r.name),
                                      pool_.get(nsr.name))) {
                    anchored = true;
                    break;
                }
            }

            if (anchored) continue;

            bool parent_anchor = false;
            auto p = parent_str(pool_.get(r.name));

            if (p.has_value()) {
                auto pid = pool_.find(*p);
                if (pid.has_value()) {
                    auto eit = explicit_clean_.find(ctx);
                    if (eit != explicit_clean_.end()) {
                        parent_anchor =
                            eit->second.find(*pid) != eit->second.end();
                    }
                }
            }

            if (!parent_anchor) {
                add_error("Orphan_Record",
                          r.name,
                          "Address record is orphan");
            }
        }
    }

    void verify_lame_delegation() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS || r.name == r.zone) continue;

            int child = r.name;
            int ns_target = r.data;

            // If the referenced server is absent from facts, treat as unknown.
            if (server_ids_.find(ns_target) == server_ids_.end()) {
                continue;
            }

            bool authoritative =
                soa_index_.find({ns_target, child}) != soa_index_.end();

            if (!authoritative) {
                add_error("No_Lame_Delegation",
                          child,
                          "NS server exists but is not authoritative: " +
                          pool_.get(ns_target));
            }
        }
    }

    void verify_delegation_consistency() {
        std::unordered_map<int, std::unordered_set<int>> parent_ns;
        std::unordered_map<int, std::unordered_set<int>> child_ns;

        parent_ns.reserve(clean_records_.size() / 32 + 1);
        child_ns.reserve(clean_records_.size() / 32 + 1);

        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS) continue;

            if (r.name != r.zone) {
                parent_ns[r.name].insert(r.data);
            } else {
                child_ns[r.zone].insert(r.data);
            }
        }

        for (const auto& [child, pset] : parent_ns) {
            const auto cit = child_ns.find(child);

            static const std::unordered_set<int> empty_set;
            const auto& cset =
                (cit == child_ns.end()) ? empty_set : cit->second;

            if (pset != cset) {
                add_error("Delegation_Consistency",
                          child,
                          "NS set mismatch between parent and child");
            }

            auto parent_zone = parent_str(pool_.get(child));
            if (!parent_zone.has_value()) continue;

            auto pzid = pool_.find(*parent_zone);
            if (!pzid.has_value()) continue;

            std::unordered_set<int> ns_union;

            for (int ns : pset) {
                if (in_zone(ns, child)) {
                    ns_union.insert(ns);
                }
            }

            for (int ns : cset) {
                if (in_zone(ns, child)) {
                    ns_union.insert(ns);
                }
            }

            for (int ns : ns_union) {
                const auto* parent_addr = addr_set_ptr(*pzid, ns);
                const auto* child_addr = addr_set_ptr(child, ns);

                if (!addr_sets_equal(parent_addr, child_addr)) {
                    add_error("Delegation_Consistency",
                              child,
                              "Inconsistent A/AAAA records for NS " +
                              pool_.get(ns));
                }
            }
        }
    }

    const std::unordered_set<uint64_t>* addr_set_ptr(int zone, int name) const {
        auto it = addr_index_.find({zone, name});
        if (it == addr_index_.end()) return nullptr;
        return &it->second;
    }

    static bool addr_sets_equal(const std::unordered_set<uint64_t>* a,
                                const std::unordered_set<uint64_t>* b) {
        if (a == nullptr && b == nullptr) return true;
        if (a == nullptr) return b->empty();
        if (b == nullptr) return a->empty();
        return *a == *b;
    }

    void verify_missing_glue() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS || r.name == r.zone) continue;

            int parent_zone = r.zone;
            int child = r.name;
            int ns = r.data;

            if (!in_zone(ns, child)) continue;

            bool has_glue =
                addr_index_.find({parent_zone, ns}) != addr_index_.end();

            if (!has_glue) {
                add_error("No_Missing_Glue_Records",
                          child,
                          "Missing glue for in-bailiwick NS: " +
                          pool_.get(ns));
            }
        }
    }

    void verify_cyclic_zone_dependency() {
        for (const auto& [start, _] : ns_dep_adj_) {
            std::unordered_set<int> seen;
            std::vector<int> stack;

            seen.reserve(64);
            stack.reserve(64);

            stack.push_back(start);

            while (!stack.empty()) {
                int cur = stack.back();
                stack.pop_back();

                if (seen.find(cur) != seen.end()) continue;
                seen.insert(cur);

                auto it = ns_dep_adj_.find(cur);
                if (it == ns_dep_adj_.end()) continue;

                for (auto [next, child] : it->second) {
                    if (next == start) {
                        add_error("No_Cyclic_Zone_Dependency",
                                  child,
                                  "Cyclic NS dependency detected involving server " +
                                  pool_.get(start));
                    } else {
                        stack.push_back(next);
                    }
                }
            }
        }
    }

    void verify_rewrite_loops() {
        for (const auto& [start, _] : alias_adj_) {
            std::unordered_set<int> seen;
            std::vector<int> stack;

            seen.reserve(32);
            stack.reserve(32);

            stack.push_back(start);

            while (!stack.empty()) {
                int cur = stack.back();
                stack.pop_back();

                if (seen.find(cur) != seen.end()) continue;
                seen.insert(cur);

                auto it = alias_adj_.find(cur);
                if (it == alias_adj_.end()) continue;

                for (int nxt : it->second) {
                    if (nxt == start) {
                        add_error("No_Rewrite_Loops",
                                  start,
                                  "Rewrite loop detected");
                    } else {
                        stack.push_back(nxt);
                    }
                }
            }
        }
    }

    void verify_rewrite_blackholing() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type == RRType::CNAME) {
                int target = r.data;

                if (belongs_to_configured_zone(target) &&
                    !can_reach_terminal_from_name(r.name)) {
                    add_error("No_Rewrite_Blackholing",
                              r.name,
                              "CNAME target cannot reach terminal answer: " +
                              pool_.get(target));
                }
            }

            if (r.type == RRType::DNAME) {
                int target = r.data;

                if (belongs_to_configured_zone(target) &&
                    !dname_target_has_terminal(r)) {
                    add_error("No_Rewrite_Blackholing",
                              r.name,
                              "DNAME target subtree cannot reach terminal answer: " +
                              pool_.get(target));
                }
            }
        }
    }

    bool can_reach_terminal_from_name(int name) const {
        auto cache_it = terminal_reach_cache_.find(name);
        if (cache_it != terminal_reach_cache_.end()) {
            return cache_it->second;
        }

        std::unordered_set<int> seen;
        std::deque<int> q;
        std::vector<int> visited;

        seen.reserve(32);
        visited.reserve(32);

        q.push_back(name);

        bool result = false;

        while (!q.empty()) {
            int cur = q.front();
            q.pop_front();

            if (seen.find(cur) != seen.end()) continue;
            seen.insert(cur);
            visited.push_back(cur);

            if (has_terminal(cur)) {
                result = true;
                break;
            }

            auto cached = terminal_reach_cache_.find(cur);
            if (cached != terminal_reach_cache_.end()) {
                result = cached->second;
                if (result) break;
                continue;
            }

            auto it = alias_adj_.find(cur);
            if (it != alias_adj_.end()) {
                for (int nxt : it->second) {
                    q.push_back(nxt);
                }
            }
        }

        for (int v : visited) {
            terminal_reach_cache_[v] = result;
        }

        return result;
    }

    bool has_terminal(int name) const {
        return terminal_names_.find(name) != terminal_names_.end();
    }

    bool dname_target_has_terminal(const Record& dname_record) const {
        int target = dname_record.data;

        auto it = dname_target_rewrite_adj_.find(target);
        if (it == dname_target_rewrite_adj_.end()) {
            return false;
        }

        for (int dst : it->second) {
            if (has_terminal(dst) || can_reach_terminal_from_name(dst)) {
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------
    // Error helper
    // ------------------------------------------------------------

    void add_error(const std::string& dim,
                   int entity,
                   const std::string& msg) {
        errors_.push_back(ErrorItem{dim, pool_.get(entity), msg});
    }
};

// ============================================================
// 5. Main
// ============================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: ./graph_verifier ZoneRecord.facts\n";
        return 1;
    }

    try {
        GraphVerifier verifier(argv[1]);

        verifier.run();
        verifier.write_outputs("Error.tsv");

        std::cout << "Verification finished.\n";
        std::cout << "Output: Error.tsv\n";
    } catch (const std::exception& e) {
        std::cerr << "Verifier error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
