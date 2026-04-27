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

enum class EdgeKind : uint8_t {
    NS_DELEGATION,
    CHILD_APEX_NS,
    CNAME_RECORD,
    CNAME_REWRITE,
    DNAME_RECORD,
    DNAME_REWRITE,
    TERMINAL,
    SUPPORT_GLUE
};

struct Record {
    int server;
    int zone;
    int name;
    RRType type;
    int data;
    size_t id;
};

struct GraphEdge {
    int src;
    int dst;
    EdgeKind kind;
    size_t record_id;
};

struct ErrorItem {
    std::string dimension;
    std::string entity;
    std::string msg;
};

struct PairHash {
    size_t operator()(const std::pair<int, int>& p) const {
        return (static_cast<size_t>(p.first) << 32) ^ static_cast<size_t>(p.second);
    }
};

using Context = std::pair<int, int>; // (server, zone)

static constexpr size_t NO_RECORD = static_cast<size_t>(-1);

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

    bool contains(const std::string& s) const {
        return id_.find(s) != id_.end();
    }

    std::optional<int> find(const std::string& s) const {
        auto it = id_.find(s);
        if (it == id_.end()) return std::nullopt;
        return it->second;
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

static bool is_descendant_str(const std::string& child, const std::string& ancestor) {
    if (child == ancestor) return false;
    if (ancestor == ".") return child != ".";
    std::string suffix = "." + ancestor;
    return ends_with(child, suffix);
}

static int domain_depth_str(const std::string& n) {
    int cnt = 0;
    for (char c : n) {
        if (c == '.') ++cnt;
    }
    return cnt;
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
    return t == RRType::A || t == RRType::AAAA || t == RRType::MX || t == RRType::TXT;
}

static std::string edge_kind_to_string(EdgeKind k) {
    switch (k) {
        case EdgeKind::NS_DELEGATION: return "NS_Delegation";
        case EdgeKind::CHILD_APEX_NS: return "Child_Apex_NS";
        case EdgeKind::CNAME_RECORD: return "CNAME_Record";
        case EdgeKind::CNAME_REWRITE: return "CNAME_Rewrite";
        case EdgeKind::DNAME_RECORD: return "DNAME_Record";
        case EdgeKind::DNAME_REWRITE: return "DNAME_Rewrite";
        case EdgeKind::TERMINAL: return "Terminal";
        case EdgeKind::SUPPORT_GLUE: return "Support_Glue";
        default: return "Unknown";
    }
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
        construct_graph_edges();
        verify_all();
    }

    void write_outputs(const std::string& error_path, const std::string& edge_path) const {
        {
            std::ofstream out(error_path);
            out << "dimension\tentity\tmessage\n";
            for (const auto& e : errors_) {
                out << e.dimension << "\t" << e.entity << "\t" << e.msg << "\n";
            }
        }

        {
            std::ofstream out(edge_path);
            out << "src\tdst\tkind\trecord_id\n";
            for (const auto& e : edges_) {
                out << pool_.get(e.src) << "\t"
                    << pool_.get(e.dst) << "\t"
                    << edge_kind_to_string(e.kind) << "\t"
                    << e.record_id << "\n";
            }
        }
    }

private:
    StringPool pool_;
    std::vector<Record> records_;
    std::vector<int> clean_records_;
    std::unordered_set<size_t> shadow_;

    std::unordered_map<Context, std::vector<int>, PairHash> records_by_ctx_;
    std::unordered_map<Context, std::vector<int>, PairHash> clean_by_ctx_;

    std::unordered_set<Context, PairHash> contexts_;
    std::unordered_set<int> server_ids_;
    std::unordered_map<int, std::vector<Context>> zone_to_contexts_;

    std::unordered_map<Context, std::unordered_set<int>, PairHash> explicit_clean_;
    std::unordered_map<Context, std::unordered_map<int, int>, PairHash> wildcard_by_encloser_;

    std::unordered_map<Context, std::unordered_set<int>, PairHash> ns_cuts_;
    std::unordered_map<Context, std::unordered_set<int>, PairHash> dname_owners_;

    std::unordered_set<size_t> glue_records_;

    std::vector<GraphEdge> edges_;
    std::vector<ErrorItem> errors_;

    std::unordered_map<int, std::vector<int>> alias_adj_;
    std::unordered_map<int, std::vector<std::pair<int, int>>> ns_dep_adj_;

private:
    // ------------------------------------------------------------
    // Loading
    // Five-column format:
    // server zone name type data
    // ------------------------------------------------------------

    void load_facts(const std::string& fact_path) {
        std::ifstream in(fact_path);
        if (!in.is_open()) {
            throw std::runtime_error("Cannot open fact file: " + fact_path);
        }

        std::string line;
        size_t id = 0;

        while (std::getline(in, line)) {
            if (line.empty()) continue;

            std::vector<std::string> cols;
            split_tab(line, cols);
            if (cols.size() < 5) continue;

            std::string server = normalize_domain(cols[0]);
            std::string zone   = normalize_domain(cols[1]);
            std::string name   = normalize_domain(cols[2]);
            std::string type_s = cols[3];
            std::string data   = cols[4];

            RRType type = parse_type(type_s);

            if (type == RRType::NS || type == RRType::CNAME || type == RRType::DNAME ||
                type == RRType::MX || type == RRType::PTR || type == RRType::SRV) {
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

    static void split_tab(const std::string& line, std::vector<std::string>& cols) {
        cols.clear();
        size_t start = 0;
        while (start <= line.size()) {
            size_t pos = line.find('\t', start);
            if (pos == std::string::npos) {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
    }

    // ------------------------------------------------------------
    // Original indices and shadow detection
    // ------------------------------------------------------------

    void build_original_indices() {
        for (int i = 0; i < static_cast<int>(records_.size()); ++i) {
            const auto& r = records_[i];

            server_ids_.insert(r.server);

            Context ctx{r.server, r.zone};
            contexts_.insert(ctx);
            records_by_ctx_[ctx].push_back(i);

            if (r.type == RRType::SOA && r.name == r.zone) {
                zone_to_contexts_[r.zone].push_back(ctx);
            }
        }

        compute_glue_records();

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
        for (const auto& [ctx, ids] : records_by_ctx_) {
            int zone = ctx.second;
            std::unordered_set<int> ns_targets;

            for (int rid : ids) {
                const auto& r = records_[rid];
                if (r.type == RRType::NS && r.name != r.zone) {
                    if (in_zone(r.data, zone)) {
                        ns_targets.insert(r.data);
                    }
                }
            }

            for (int rid : ids) {
                const auto& r = records_[rid];
                if ((r.type == RRType::A || r.type == RRType::AAAA) &&
                    ns_targets.find(r.name) != ns_targets.end()) {
                    glue_records_.insert(r.id);
                }
            }
        }
    }

    void detect_shadow_records() {
        for (const auto& [ctx, ids] : records_by_ctx_) {
            for (int rid : ids) {
                const auto& r = records_[rid];

                bool occ_ns = has_ancestor_in_set(r.name, ns_cuts_[ctx]);
                bool occ_d  = has_ancestor_in_set(r.name, dname_owners_[ctx]);

                if (occ_ns && glue_records_.find(r.id) == glue_records_.end()) {
                    shadow_.insert(r.id);
                    add_error("Shadow_Record", r.name, "Occluded by NS delegation");
                }

                if (occ_d && r.type != RRType::DNAME) {
                    shadow_.insert(r.id);
                    add_error("Shadow_Record", r.name, "Occluded by DNAME subtree rewrite");
                }
            }
        }
    }

    bool has_ancestor_in_set(int name, const std::unordered_set<int>& ancestors) {
        std::string cur = pool_.get(name);

        while (true) {
            auto p = parent_str(cur);
            if (!p.has_value()) return false;

            auto pid = pool_.find(*p);
            if (pid.has_value() && ancestors.find(*pid) != ancestors.end()) {
                return true;
            }

            if (*p == ".") return false;
            cur = *p;
        }
    }

    void build_clean_indices() {
        for (int i = 0; i < static_cast<int>(records_.size()); ++i) {
            if (shadow_.find(records_[i].id) != shadow_.end()) continue;

            clean_records_.push_back(i);
            const auto& r = records_[i];

            Context ctx{r.server, r.zone};
            clean_by_ctx_[ctx].push_back(i);
            explicit_clean_[ctx].insert(r.name);

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

    std::vector<Context> closest_contexts_for_name(int target) const {
        std::vector<Context> best;
        int best_depth = -1;

        const std::string& t = pool_.get(target);

        for (const auto& [zone, ctxs] : zone_to_contexts_) {
            const std::string& z = pool_.get(zone);
            bool belongs = (t == z || is_descendant_str(t, z));
            if (!belongs) continue;

            int d = domain_depth_str(z);
            if (d > best_depth) {
                best_depth = d;
                best = ctxs;
            } else if (d == best_depth) {
                best.insert(best.end(), ctxs.begin(), ctxs.end());
            }
        }

        return best;
    }

    std::optional<int> exact_or_wildcard_match(Context ctx, int query) const {
        auto eit = explicit_clean_.find(ctx);
        if (eit != explicit_clean_.end() && eit->second.find(query) != eit->second.end()) {
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
        return !closest_contexts_for_name(name).empty();
    }

    // ------------------------------------------------------------
    // Graph construction
    // ------------------------------------------------------------

    void construct_graph_edges() {
        construct_terminal_edges();
        construct_cname_edges();
        construct_dname_edges();
        construct_ns_delegation_edges();
        construct_child_apex_ns_edges();
        construct_support_glue_edges();
    }

    void add_edge(int src, int dst, EdgeKind kind, size_t record_id = NO_RECORD) {
        edges_.push_back(GraphEdge{src, dst, kind, record_id});
    }

    void construct_terminal_edges() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];
            if (is_terminal_type(r.type)) {
                add_edge(r.name, r.data, EdgeKind::TERMINAL, r.id);
            }
        }
    }

    void construct_cname_edges() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];
            if (r.type != RRType::CNAME) continue;

            add_edge(r.name, r.data, EdgeKind::CNAME_RECORD, r.id);

            auto contexts = closest_contexts_for_name(r.data);

            for (Context ctx : contexts) {
                auto matched = exact_or_wildcard_match(ctx, r.data);
                if (!matched.has_value()) continue;

                if (*matched != r.data) {
                    add_edge(r.data, *matched, EdgeKind::CNAME_REWRITE, r.id);
                }

                alias_adj_[r.name].push_back(*matched);
            }
        }
    }

    void construct_dname_edges() {
        std::vector<int> all_names = collect_all_names();

        for (int rid : clean_records_) {
            const auto& r = records_[rid];
            if (r.type != RRType::DNAME) continue;

            int owner = r.name;
            int target_root = r.data;

            add_edge(owner, target_root, EdgeKind::DNAME_RECORD, r.id);

            auto target_contexts = closest_contexts_for_name(target_root);
            for (Context ctx : target_contexts) {
                auto cit = clean_by_ctx_.find(ctx);
                if (cit == clean_by_ctx_.end()) continue;

                for (int crid : cit->second) {
                    const auto& cr = records_[crid];
                    if (is_descendant_str(pool_.get(cr.name), pool_.get(target_root))) {
                        add_edge(target_root, cr.name, EdgeKind::DNAME_REWRITE, r.id);
                    }
                }
            }

            for (int src : all_names) {
                if (!is_descendant_str(pool_.get(src), pool_.get(owner))) continue;

                int rewritten = dname_rewrite(src, owner, target_root);

                if (static_cast<int>(pool_.get(rewritten).size()) > 255) {
                    add_error("No_Query_Exceeds_Maximum_Length",
                              src,
                              "Query exceeds 255 bytes after DNAME rewrite");
                }

                auto contexts = closest_contexts_for_name(rewritten);

                for (Context ctx : contexts) {
                    auto matched = exact_or_wildcard_match(ctx, rewritten);
                    if (!matched.has_value()) continue;

                    if (*matched != rewritten) {
                        add_edge(rewritten, *matched, EdgeKind::DNAME_REWRITE, r.id);
                    }

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

    void construct_ns_delegation_edges() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS || r.name == r.zone) continue;

            int parent_server = r.server;
            int child = r.name;
            int ns_target = r.data;

            ns_dep_adj_[parent_server].push_back({ns_target, child});

            if (server_ids_.find(ns_target) == server_ids_.end()) {
                continue;
            }

            Context child_ctx{ns_target, child};

            bool child_exists = false;
            auto cit = clean_by_ctx_.find(child_ctx);
            if (cit != clean_by_ctx_.end()) {
                for (int crid : cit->second) {
                    const auto& cr = records_[crid];
                    if (cr.type == RRType::SOA && cr.name == child) {
                        child_exists = true;
                        break;
                    }
                }
            }

            if (!child_exists) {
                continue;
            }

            for (int crid : clean_by_ctx_[child_ctx]) {
                const auto& cr = records_[crid];

                if (cr.name == child || is_descendant_str(pool_.get(cr.name), pool_.get(child))) {
                    add_edge(ns_target, cr.name, EdgeKind::NS_DELEGATION, r.id);
                }
            }
        }
    }

    void construct_child_apex_ns_edges() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type == RRType::NS && r.name == r.zone) {
                add_edge(r.name, r.data, EdgeKind::CHILD_APEX_NS, r.id);
            }
        }
    }

    void construct_support_glue_edges() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if ((r.type == RRType::A || r.type == RRType::AAAA) &&
                glue_records_.find(r.id) != glue_records_.end() &&
                shadow_.find(r.id) == shadow_.end()) {
                add_edge(r.name, r.data, EdgeKind::SUPPORT_GLUE, r.id);
            }
        }
    }

    std::vector<int> collect_all_names() {
        std::unordered_set<int> s;
        for (const auto& r : records_) {
            s.insert(r.name);
            if (r.type == RRType::NS || r.type == RRType::CNAME ||
                r.type == RRType::DNAME || r.type == RRType::MX ||
                r.type == RRType::PTR || r.type == RRType::SRV) {
                s.insert(r.data);
            }
        }
        return std::vector<int>(s.begin(), s.end());
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
            if (!(r.type == RRType::A || r.type == RRType::AAAA)) continue;

            Context ctx{r.server, r.zone};

            bool has_deleg = false;
            bool anchored = false;

            auto it = clean_by_ctx_.find(ctx);
            if (it == clean_by_ctx_.end()) continue;

            for (int nrid : it->second) {
                const auto& nsr = records_[nrid];
                if (nsr.type != RRType::NS || nsr.name == nsr.zone) continue;

                has_deleg = true;

                if (r.name == nsr.data ||
                    r.name == nsr.name ||
                    is_descendant_str(pool_.get(r.name), pool_.get(nsr.name))) {
                    anchored = true;
                    break;
                }
            }

            if (!has_deleg) continue;

            bool parent_anchor = false;
            auto p = parent_str(pool_.get(r.name));
            if (p.has_value()) {
                auto pid = pool_.find(*p);
                if (pid.has_value()) {
                    parent_anchor = explicit_clean_[ctx].find(*pid) != explicit_clean_[ctx].end();
                }
            }

            if (!anchored && !parent_anchor) {
                add_error("Orphan_Record", r.name, "Address record is orphan");
            }
        }
    }

    void verify_lame_delegation() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS || r.name == r.zone) continue;

            int child = r.name;
            int ns_target = r.data;

            if (server_ids_.find(ns_target) == server_ids_.end()) {
                continue;
            }

            bool authoritative = false;
            Context child_ctx{ns_target, child};
            auto it = clean_by_ctx_.find(child_ctx);

            if (it != clean_by_ctx_.end()) {
                for (int crid : it->second) {
                    const auto& cr = records_[crid];
                    if (cr.type == RRType::SOA && cr.name == child) {
                        authoritative = true;
                        break;
                    }
                }
            }

            if (!authoritative) {
                add_error("No_Lame_Delegation",
                          child,
                          "NS server exists but is not authoritative: " + pool_.get(ns_target));
            }
        }
    }

    void verify_delegation_consistency() {
        std::unordered_map<int, std::unordered_set<int>> parent_ns;
        std::unordered_map<int, std::unordered_set<int>> child_ns;

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
            const std::unordered_set<int> empty_set;
            const auto& cset = (cit == child_ns.end()) ? empty_set : cit->second;

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
                auto parent_addr = addr_set(*pzid, ns);
                auto child_addr = addr_set(child, ns);

                if (parent_addr != child_addr) {
                    add_error("Delegation_Consistency",
                              child,
                              "Inconsistent A/AAAA records for NS " + pool_.get(ns));
                }
            }
        }
    }

    std::unordered_set<std::string> addr_set(int zone, int name) const {
        std::unordered_set<std::string> s;

        for (int rid : clean_records_) {
            const auto& r = records_[rid];
            if (r.zone == zone && r.name == name &&
                (r.type == RRType::A || r.type == RRType::AAAA)) {
                s.insert(type_to_string(r.type) + ":" + pool_.get(r.data));
            }
        }

        return s;
    }

    void verify_missing_glue() {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];

            if (r.type != RRType::NS || r.name == r.zone) continue;

            int parent_zone = r.zone;
            int child = r.name;
            int ns = r.data;

            if (!in_zone(ns, child)) continue;

            bool has_glue = false;
            for (int crid : clean_records_) {
                const auto& gr = records_[crid];
                if (gr.zone == parent_zone && gr.name == ns &&
                    (gr.type == RRType::A || gr.type == RRType::AAAA)) {
                    has_glue = true;
                    break;
                }
            }

            if (!has_glue) {
                add_error("No_Missing_Glue_Records",
                          child,
                          "Missing glue for in-bailiwick NS: " + pool_.get(ns));
            }
        }
    }

    void verify_cyclic_zone_dependency() {
        for (const auto& [start, _] : ns_dep_adj_) {
            std::unordered_set<int> seen;
            std::vector<int> stack;
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
                                  "Cyclic NS dependency detected involving server " + pool_.get(start));
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
                        add_error("No_Rewrite_Loops", start, "Rewrite loop detected");
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
                if (belongs_to_configured_zone(target) && !can_reach_terminal_from_name(r.name)) {
                    add_error("No_Rewrite_Blackholing",
                              r.name,
                              "CNAME target cannot reach terminal answer: " + pool_.get(target));
                }
            }

            if (r.type == RRType::DNAME) {
                int target = r.data;
                if (belongs_to_configured_zone(target) && !dname_target_has_terminal(r)) {
                    add_error("No_Rewrite_Blackholing",
                              r.name,
                              "DNAME target subtree cannot reach terminal answer: " + pool_.get(target));
                }
            }
        }
    }

    bool can_reach_terminal_from_name(int name) const {
        std::unordered_set<int> seen;
        std::deque<int> q;
        q.push_back(name);

        while (!q.empty()) {
            int cur = q.front();
            q.pop_front();

            if (seen.find(cur) != seen.end()) continue;
            seen.insert(cur);

            if (has_terminal(cur)) return true;

            auto it = alias_adj_.find(cur);
            if (it != alias_adj_.end()) {
                for (int nxt : it->second) {
                    q.push_back(nxt);
                }
            }
        }

        return false;
    }

    bool has_terminal(int name) const {
        for (int rid : clean_records_) {
            const auto& r = records_[rid];
            if (r.name == name && is_terminal_type(r.type)) {
                return true;
            }
        }
        return false;
    }

    bool dname_target_has_terminal(const Record& dname_record) const {
        int target = dname_record.data;

        for (const auto& e : edges_) {
            if (e.src == target && e.kind == EdgeKind::DNAME_REWRITE) {
                if (has_terminal(e.dst) || can_reach_terminal_from_name(e.dst)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ------------------------------------------------------------
    // Error helper
    // ------------------------------------------------------------

    void add_error(const std::string& dim, int entity, const std::string& msg) {
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
        verifier.write_outputs("Error.tsv", "GraphEdge.tsv");

        std::cout << "Verification finished.\n";
        std::cout << "Outputs: Error.tsv, GraphEdge.tsv\n";
    } catch (const std::exception& e) {
        std::cerr << "Verifier error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}