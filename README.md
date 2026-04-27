
# GraphDNS: Resolution Relation Graph Abstraction for Large-Scale Analysis of Static DNS Configurations

<p align="center">
  <img src="https://img.shields.io/badge/platform-Ubuntu%2022.04-orange" alt="platform">
  <img src="https://img.shields.io/badge/language-C%2B%2B17-purple" alt="language">
  <img src="https://img.shields.io/badge/domain-DNS%20Security-red" alt="domain">
  <img src="https://img.shields.io/badge/scalability-10M%2B%20records-success" alt="scalability">
</p>

---

## Overview

**GraphDNS** is a research-oriented framework for large-scale static DNS configuration analysis.

GraphDNS analyzes DNS configurations by constructing a **resolution relation graph** from static zone files. It then applies local-priority filtering, derives a reachable view over the purified graph, and checks multiple classes of DNS configuration anomalies over the resulting graph structures.

The current implementation is written in **C++17** and consists of two executable programs:

1. `preprocess`: parses zone files and generates normalized record tuples.
2. `graph_verifier`: loads the generated tuples, constructs the resolution relation graph, and performs anomaly detection.

GraphDNS currently detects three broad classes of DNS configuration anomalies:

- **Path vulnerabilities**
- **Orphan records**
- **Shadow records**

The framework is designed for offline analysis of static authoritative DNS configurations. It does not issue live DNS queries and does not depend on recursive resolvers.

---

## Repository Structure

A typical repository layout is:

```text
GraphDNS/
├── src/
│   ├── preprocess.cpp          # Zone-file parser and tuple generator
│   ├── graph_verifier.cpp      # Graph construction and anomaly detection engine
│   └── run_experiments.sh      # Large-scale performance testing script
├── synthetic_dataset/
│   ├── example-domain/
│   │   ├── zone1.txt
│   │   ├── zone2.txt
│   │   └── metadata.json
│   └── ...
├── census/
│   └── ...                     # Optional large-scale dataset
└── README.md
````

---

## Environment Requirements

### Hardware Requirements

Recommended:

* CPU: multi-core x86-64 processor
* Memory: 8 GB or higher
* Storage: SSD recommended for large datasets

For large-scale experiments over millions of records, storage and I/O bandwidth may become the dominant bottleneck.

### Software Requirements

* Operating system: Ubuntu 22.04.5 LTS or compatible Linux distribution
* Compiler: `g++` with C++17 support
* OpenMP support
* JSON library: `nlohmann/json.hpp`

On Ubuntu, install the required packages with:

```bash
sudo apt update
sudo apt install -y g++ make libomp-dev nlohmann-json3-dev
```

If `nlohmann/json.hpp` is already vendored in your project or available in your include path, installing `nlohmann-json3-dev` is not necessary.

---

## Dataset Layout

GraphDNS expects the input dataset to be organized as directories containing zone files and a corresponding `metadata.json`.

Example:

```text
dataset/
├── a.com/
│   ├── 1.a.com.txt
│   ├── 2.a.com.txt
│   └── metadata.json
└── b.com/
    ├── 1.b.com.txt
    ├── 2.b.com.txt
    └── metadata.json
```

Each `*.txt` file stores one DNS zone file.

Each directory must contain a `metadata.json` file describing the zone files in that directory.

Example `metadata.json`:

```json
{
  "ZoneFiles": [
    {
      "FileName": "1.a.com.txt",
      "NameServer": "ns1.a.com.",
      "Origin": "a.com."
    },
    {
      "FileName": "2.a.com.txt",
      "NameServer": "ns2.a.com.",
      "Origin": "sub.a.com."
    }
  ]
}
```

### Metadata Fields

| Field        | Required | Meaning                                                          |
| ------------ | -------: | ---------------------------------------------------------------- |
| `FileName`   |      Yes | Name of the zone-file text file                                  |
| `NameServer` |      Yes | Authoritative server hosting this zone file                      |
| `Origin`     | Optional | Zone apex. If omitted, GraphDNS infers it from the filename stem |

If `Origin` is absent, a file named `example.com.txt` is interpreted as the zone apex `example.com.`.

---

## Build Instructions

GraphDNS currently builds two executables:

* `preprocess`
* `graph_verifier`

### Step 1: Compile the Preprocessor

```bash
g++ -O3 -std=c++17 -fopenmp preprocess.cpp -o preprocess
```

### Step 2: Compile the Graph Verifier

```bash
g++ -O3 -std=c++17 -fopenmp graph_verifier.cpp -o graph_verifier
```

---

## Verification Workflow

This is the standard workflow for running GraphDNS on a dataset.

### Step 1: Generate `ZoneRecord.facts`

```bash
./preprocess ../synthetic_dataset
```

### Step 2: Run Graph-Based Verification

```bash
./graph_verifier ZoneRecord.facts
```

### Step 3: Inspect Outputs

GraphDNS produces an output file: Error.tsv, which contains detected configuration anomalies.

Format:

```text
dimension    entity    message
```

Example:

```text
No_Rewrite_Blackholing    old.example.com.    CNAME target cannot reach terminal answer: target.example.com.
No_Lame_Delegation        sub.example.com.    NS server exists but is not authoritative: ns1.sub.example.com.
Shadow_Record             stale.sub.example.com.    Occluded by NS delegation
```

---

## Large-Scale Performance Evaluation

GraphDNS supports large-scale experiments by running preprocessing and verification repeatedly under different record-count limits.


```bash
chmod +x run_experiments.sh
```

Run:

```bash
./run_experiments.sh
```

---

## Public Large-Scale Dataset

The Census dataset can be used for large-scale evaluation. Public source: https://zenodo.org/records/3905968
