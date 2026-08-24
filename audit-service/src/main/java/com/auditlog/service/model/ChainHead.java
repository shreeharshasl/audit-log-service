package com.auditlog.service.model;

/** The tip of the chain: the last sequence number issued and the hash the next record links to. */
public record ChainHead(long lastSeq, String lastChainHashHex) {}
