# DID-Manipulating-Trojan

## Introduction 

In order to reduce time-to-market and overall cost of microprocessors used in embedded systems and Internet-of-Things sectors,
System-on-Chips (SoCs) started housing third party Intellectual
Property(IP) blocks. Due to the high design cost, many chip manufacturing industries rely on outsourcing design automation, fabrication, and testing of integrated circuits. Functional and logical security of such devices is at stake due to the involvement of untrusted
third parties during various phases of chip manufacturing. Malicious circuits, known as Hardware Trojan (HT) implanted inside a
genuine blueprint design can go untraceable during the verification
and testing phase of SoC. HTs can alter the system behavior to
deploy attacks such as information leakage, unauthorized access,
functional errors, and delay-of-service

Tiled Chip Multicore Processors (TCMP) uses Network on Chip (NoC) for inter tile communication. NoC being the communication backbone of TCMP is a prime
spot for mounting HT attacks. Since, NoC has access to data that travel between tiles, an HT infected router is capable of performing data corruption, stealing sensitive information and impacting QoS. 

## Project Contribution

This project specifically focuses on HTs that can manipulate packet header. To the best of our knowledge, no other work explored packet header attacks in
NoC based systems and conducted in depth study on the impacts created by such attacks. This project shall also throw light on Mitigation mechanism for such HTs.

## Trojan Model




