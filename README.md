# SIN (Shadows In The Network)

SIN is an automated security agent designed for distributed IoT network assessment. It autonomously discovers network assets, fingerprints services, and identifies potential vulnerabilities in enterprise environments.

## Architecture

The system follows a modular architecture:
- **Agent**: Core orchestration logic (`src/sin/agent`)
- **Discovery**: Network reconnaissance and topology mapping (`src/sin/discovery`)
- **Scanner**: Vulnerability assessment modules (`src/sin/scanner`)
- **Intelligence**: Data analysis and risk scoring (`src/sin/intelligence`)

## Getting Started

### Prerequisites
- Python 3.10+
- Virtual Environment (recommended)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/drvigilant/sin.git
   cd sin
