# CSCE 465 HW 2 User Setup

## Environment Summary

- Home operating system: Windows
- Hypervisor: VMware Workstation Pro
- VM: Ubuntu 24.04 LTS x86-64
- Memory: 8 GB RAM
- Processors: 4 vCPUs
- Networking: NAT only

## Python Environment Setup

Folder Structure:

```text
csce465-agentsec/
└── hw2/
    ├── baseline_ctr.py
    ├── handshake.py
    ├── secure_record.py
    ├── ffdhe3072.pem
    └── tests/
```

Create and activate the Python environment:

```bash
cd ~/csce465-agentsec
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

If virtual environment support is missing:

```bash
sudo apt install python3-venv
```

Check the installed versions:

```bash
python3 --version
openssl version
python -m pip show cryptography pytest
```

## Diffie-Hellman Parameters

The submission includes `ffdhe3072.pem`. Check it with:

```bash
cd ~/csce465-agentsec/hw2
openssl dhparam -in ffdhe3072.pem -text -noout
```

To generate the file again if needed:

```bash
openssl genpkey -genparam -algorithm DH \
    -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```


## Running the Demonstrations

Activate the environment and enter the assignment folder:

```bash
cd ~/csce465-agentsec
source .venv/bin/activate
cd hw2
```

Run the AES-CTR modification and replay demonstration:

```bash
python baseline_ctr.py
```

Run the authenticated Diffie-Hellman handshake:

```bash
python handshake.py
```

Run the protected record demonstration:

```bash
python secure_record.py
```

## Running the Tests

Run this command from inside `hw2`:

```bash
PYTHONPATH=.. python -m pytest -v tests
```

The tests cover valid communication, modified ciphertext, a modified header, replay, reflection into the wrong direction, and verification with an incorrect RSA public key.

## Submission Files

- `report.pdf`: explanations, results, and security note
- `README.md`: setup and running instructions
- `AI_USAGE.md` and corresponding AI logs
- Python source files, `ffdhe3072.pem`, and `tests/`

## Known Issues

If the handshake cannot find `ffdhe3072.pem`, make sure you are running it from inside `hw2`.

If the tests cannot import `hw2`, keep the folder named `hw2` and use the test command shown above.
