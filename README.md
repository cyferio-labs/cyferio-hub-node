# Cyferio Hub

Cyferio Hub is a confidential rollup router designed to bring scalability, privacy, and interoperability to blockchain ecosystems such as Ethereum, Bitcoin, and Solana. Together with the [Cyferio SDK](https://github.com/cyferio-labs/cyferio-sdk), which complements this by simplifying the creation and management of confidential (FHE-based) rollups, offering developers a straightforward way to build privacy-preserving applications.


## Overview

Cyferio Hub, built on top of Substrate, serves as a cache layer that links rollups across various blockchain networks. This integration simplifies cross-chain communication, enhances scalability, and allows developers to easily build and deploy confidential applications to different ecosystems.

<p align="center">
 <img src="assets/general/Cyferio Hub Arch.jpg" alt="Cyferio Hub Architecture"/>
    <br>
    <em>Architecture of Cyferio Hub</em>
</p>

## Project Details

Overall, Cyferio Labs' solutions aim to unlock confidential applications with FHE rollups that are connected to blockchain ecosystems. We provide fundamental infrastructures for confidential applications, with Cyferio SDK serving as the FHE rollup framework and Cyferio Hub as a rollup router connecting these confidential rollups to the L1/L2 blockchains, Data Availability Layers, and other ecosystems. Since Cyferio Hub is built on top of Substrate, it is highly modular and can be easily integrated with other ecosystems. We empower developers to build applications with advanced privacy-preserving use cases beyond the capabilities of general-purpose FHE rollups.

Additionally, scalability and transaction processing speed will be significantly enhanced through our collaboration with DragonflyDB to develop an in-memory storage solution. This integration ensures robust support for cross-chain interoperability and delivers a scalable, high-performance solution tailored for large-scale transaction processing of FHE rollups.

## Getting Started

### Build

Use the following command to build the node without launching it:

```sh
cargo build --release
```

### Local Single-Node Development Chain

The following command starts a single-node development chain that doesn't
persist state:

```sh
./target/release/cyferio-hub-node --dev --unsafe-rpc-external
```
